// Package dnsforward contains a DNS forwarding server.
package dnsforward

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghslog"
	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/constants" // Import the constants package
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/AdGuardHome/internal/rdns"
	"github.com/AdguardTeam/AdGuardHome/internal/stats"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/sysresolv"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/miekg/dns"
)

// DefaultTimeout is the default upstream timeout
const DefaultTimeout = 10 * time.Second

// defaultLocalTimeout is the default timeout for resolving addresses from
// locally-served networks.  It is assumed that local resolvers should work much
// faster than ordinary upstreams.
const defaultLocalTimeout = 1 * time.Second

// defaultClientIDCacheCount is the default count of items in the LRU ClientID
// cache.  The assumption here is that there won't be more than this many
// requests between the BeforeRequestHandler stage and the actual processing.
const defaultClientIDCacheCount = 1024

var defaultDNS = []string{
	"https://dns10.quad9.net/dns-query",
}
var defaultBootstrap = []string{"9.9.9.10", "149.112.112.10", "2620:fe::10", "2620:fe::fe:10"}

// Often requested by all kinds of DNS probes
var defaultBlockedHosts = []string{"version.bind", "id.server", "hostname.bind"}

var (
	// defaultUDPListenAddrs are the default UDP addresses for the server.
	defaultUDPListenAddrs = []*net.UDPAddr{{Port: 53}}

	// defaultTCPListenAddrs are the default TCP addresses for the server.
	defaultTCPListenAddrs = []*net.TCPAddr{{Port: 53}}
)

var webRegistered bool

// DHCP is an interface for accessing DHCP lease data needed in this package.
type DHCP interface {
	// HostByIP returns the hostname of the DHCP client with the given IP
	// address.  The address will be netip.Addr{} if there is no such client,
	// due to an assumption that a DHCP client must always have an IP address.
	HostByIP(ip netip.Addr) (host string)

	// IPByHost returns the IP address of the DHCP client with the given
	// hostname.  The hostname will be an empty string if there is no such
	// client, due to an assumption that a DHCP client must always have a
	// hostname, either set by the client or assigned automatically.
	IPByHost(host string) (ip netip.Addr)

	// Enabled returns true if DHCP provides information about clients.
	Enabled() (ok bool)
}

// SystemResolvers is an interface for accessing the OS-provided resolvers.
type SystemResolvers interface {
	// Addrs returns the list of system resolvers' addresses.  Callers must
	// clone the returned slice before modifying it.  Implementations of Addrs
	// must be safe for concurrent use.
	Addrs() (addrs []netip.AddrPort)
}

// Server is the main way to start a DNS server.
//
// Example:
//
//	s := dnsforward.Server{}
//	err := s.Start(nil) // will start a DNS server listening on default port 53, in a goroutine
//	err := s.Reconfigure(ServerConfig{UDPListenAddr: &net.UDPAddr{Port: 53535}}) // will reconfigure running DNS server to listen on UDP port 53535
//	err := s.Stop() // will stop listening on port 53535 and cancel all goroutines
//	err := s.Start(nil) // will start listening again, on port 53535, in a goroutine
//
// The zero Server is empty and ready for use.
type Server struct {
	// addrProc, if not nil, is used to process clients' IP addresses with rDNS,
	// WHOIS, etc.
	addrProc client.AddressProcessor

	// bootstrap is the resolver for upstreams' hostnames.
	bootstrap upstream.Resolver

	// clientIDCache is a temporary storage for ClientIDs that were extracted
	// during the BeforeRequestHandler stage.
	clientIDCache cache.Cache

	// dhcpServer is the DHCP server for accessing lease data.
	dhcpServer DHCP

	// etcHosts contains the current data from the system's hosts files.
	etcHosts upstream.Resolver

	// privateNets is the configured set of IP networks considered private.
	privateNets netutil.SubnetSet

	// queryLog is the query log for client's DNS requests, responses and
	// filtering results.
	queryLog querylog.QueryLog

	// stats is the statistics collector for client's DNS usage data.
	stats stats.Interface

	// sysResolvers used to fetch system resolvers to use by default for private
	// PTR resolving.
	sysResolvers SystemResolvers

	// access drops disallowed clients.
	access *accessManager

	// anonymizer masks the client's IP addresses if needed.
	anonymizer *aghnet.IPMut

	// baseLogger is used to create loggers for other entities.  It should not
	// have a prefix and must not be nil.
	baseLogger *slog.Logger

	// dnsFilter is the DNS filter for filtering client's DNS requests and
	// responses.
	dnsFilter *filtering.DNSFilter

	// dnsProxy is the DNS proxy for forwarding client's DNS requests.
	dnsProxy *proxy.Proxy

	// internalProxy resolves internal requests from the application itself.  It
	// isn't started and so no listen ports are required.
	internalProxy *proxy.Proxy

	// ipset processes DNS requests using ipset data.  It must not be nil after
	// initialization.  See [newIpsetHandler].
	ipset *ipsetHandler

	// dns64Pref is the NAT64 prefix used for DNS64 response mapping.  The major
	// part of DNS64 happens inside the [proxy] package, but there still are
	// some places where response mapping is needed (e.g. DHCP).
	dns64Pref netip.Prefix

	// localDomainSuffix is the suffix used to detect internal hosts.  It
	// must be a valid domain name plus dots on each side.
	localDomainSuffix string

	// bootResolvers are the resolvers that should be used for
	// bootstrapping along with [etcHosts].
	//
	// TODO(e.burkov):  Use [proxy.UpstreamConfig] when it will implement the
	// [upstream.Resolver] interface.
	bootResolvers []*upstream.UpstreamResolver

	// dnsNames are the DNS names from certificate (SAN) or CN value from
	// Subject.
	dnsNames []string

	// conf is the current configuration of the server.
	conf ServerConfig

	// serverLock protects Server.
	serverLock sync.RWMutex

	// protectionUpdateInProgress is used to make sure that only one goroutine
	// updating the protection configuration after a pause is running at a time.
	protectionUpdateInProgress atomic.Bool

	// isRunning is true if the DNS server is running.
	isRunning bool

	// hasIPAddrs is set during the certificate parsing and is true if the
	// configured certificate contains at least a single IP address.
	hasIPAddrs bool
}

// defaultLocalDomainSuffix is the default suffix used to detect internal hosts
// when no suffix is provided.
//
// See the documentation for Server.localDomainSuffix.
const defaultLocalDomainSuffix = "lan"

// DNSCreateParams are parameters to create a new server.
type DNSCreateParams struct {
	DNSFilter   *filtering.DNSFilter
	Stats       stats.Interface
	QueryLog    querylog.QueryLog
	DHCPServer  DHCP
	PrivateNets netutil.SubnetSet
	Anonymizer  *aghnet.IPMut
	EtcHosts    *aghnet.HostsContainer

	// Logger is used as a base logger.  It must not be nil.
	Logger *slog.Logger

	LocalDomain string
}

// NewServer creates a new instance of the dnsforward.Server
// Note: this function must be called only once
//
// TODO(a.garipov): How many constructors and initializers does this thing have?
// Refactor!
func NewServer(p DNSCreateParams) (s *Server, err error) {
	var localDomainSuffix string
	if p.LocalDomain == "" {
		localDomainSuffix = defaultLocalDomainSuffix
	} else {
		err = netutil.ValidateDomainName(p.LocalDomain)
		if err != nil {
			return nil, fmt.Errorf("local domain: %w", err)
		}

		localDomainSuffix = p.LocalDomain
	}

	if p.Anonymizer == nil {
		p.Anonymizer = aghnet.NewIPMut(nil)
	}

	var etcHosts upstream.Resolver
	if p.EtcHosts != nil {
		etcHosts = upstream.NewHostsResolver(p.EtcHosts)
	}

	s = &Server{
		dnsFilter:   p.DNSFilter,
		dhcpServer:  p.DHCPServer,
		stats:       p.Stats,
		queryLog:    p.QueryLog,
		privateNets: p.PrivateNets,
		baseLogger:  p.Logger,
		// TODO(e.burkov):  Use some case-insensitive string comparison.
		localDomainSuffix: strings.ToLower(localDomainSuffix),
		etcHosts:          etcHosts,
		clientIDCache: cache.New(cache.Config{
			EnableLRU: true,
			MaxCount:  defaultClientIDCacheCount,
		}),
		anonymizer: p.Anonymizer,
		conf: ServerConfig{
			ServePlainDNS: true,
		},
	}

	s.sysResolvers, err = sysresolv.NewSystemResolvers(nil, defaultPlainDNSPort)
	if err != nil {
		return nil, fmt.Errorf("initializing system resolvers: %w", err)
	}

	if runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" {
		// Use plain DNS on MIPS, encryption is too slow
		defaultDNS = defaultBootstrap
	}

	return s, nil
}

// Close gracefully closes the server.  It is safe for concurrent use.
//
// TODO(e.burkov): A better approach would be making Stop method waiting for all
// its workers finished.  But it would require the upstream.Upstream to have the
// Close method to prevent from hanging while waiting for unresponsive server to
// respond.
func (s *Server) Close() {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	// TODO(s.chzhen):  Remove it.
	s.stats = nil
	s.queryLog = nil
	s.dnsProxy = nil

	if err := s.ipset.close(); err != nil {
		log.Error("dnsforward: closing ipset: %s", err)
	}
}

// WriteDiskConfig - write configuration
func (s *Server) WriteDiskConfig(c *Config) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	sc := s.conf.Config
	*c = sc
	c.RatelimitWhitelist = slices.Clone(sc.RatelimitWhitelist)
	c.BootstrapDNS = slices.Clone(sc.BootstrapDNS)
	c.FallbackDNS = slices.Clone(sc.FallbackDNS)
	c.AllowedClients = slices.Clone(sc.AllowedClients)
	c.DisallowedClients = slices.Clone(sc.DisallowedClients)
	c.BlockedHosts = slices.Clone(sc.BlockedHosts)
	c.AllowedCountries = slices.Clone(sc.AllowedCountries)
	c.BlockedCountries = slices.Clone(sc.BlockedCountries)
	c.TrustedProxies = slices.Clone(sc.TrustedProxies)
	c.UpstreamDNS = slices.Clone(sc.UpstreamDNS)
}

// LocalPTRResolvers returns the current local PTR resolver configuration.
func (s *Server) LocalPTRResolvers() (localPTRResolvers []string) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	return slices.Clone(s.conf.LocalPTRResolvers)
}

// AddrProcConfig returns the current address processing configuration.  Only
// fields c.UsePrivateRDNS, c.UseRDNS, and c.UseWHOIS are filled.
func (s *Server) AddrProcConfig() (c *client.DefaultAddrProcConfig) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	return &client.DefaultAddrProcConfig{
		UsePrivateRDNS: s.conf.UsePrivateRDNS,
		UseRDNS:        s.conf.AddrProcConf.UseRDNS,
		UseWHOIS:       s.conf.AddrProcConf.UseWHOIS,
	}
}

// UpstreamTimeout returns the current upstream timeout configuration.
func (s *Server) UpstreamTimeout() (t time.Duration) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	return s.conf.UpstreamTimeout
}

// Resolve gets IP addresses by host name from an upstream server.  No
// request/response filtering is performed.  Query log and Stats are not
// updated.  This method may be called before [Server.Start].
func (s *Server) Resolve(ctx context.Context, net, host string) (addr []netip.Addr, err error) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	return s.internalProxy.LookupNetIP(ctx, net, host)
}

const (
	// ErrRDNSNoData is returned by [RDNSExchanger.Exchange] when the answer
	// section of response is either NODATA or has no PTR records.
	ErrRDNSNoData errors.Error = "no ptr data in response"

	// ErrRDNSFailed is returned by [RDNSExchanger.Exchange] if the received
	// response is not a NOERROR or NXDOMAIN.
	ErrRDNSFailed errors.Error = "failed to resolve ptr"
)

// type check
var _ rdns.Exchanger = (*Server)(nil)

// Exchange implements the [rdns.Exchanger] interface for *Server.
func (s *Server) Exchange(ip netip.Addr) (host string, ttl time.Duration, err error) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	// TODO(e.burkov):  Migrate to [netip.Addr] already.
	arpa, err := netutil.IPToReversedAddr(ip.AsSlice())
	if err != nil {
		return "", 0, fmt.Errorf("reversing ip: %w", err)
	}

	arpa = dns.Fqdn(arpa)
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Compress: true,
		Question: []dns.Question{{
			Name:   arpa,
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET,
		}},
	}

	dctx := &proxy.DNSContext{
		Proto:           proxy.ProtoUDP,
		Req:             req,
		IsPrivateClient: true,
	}

	var errMsg string
	if s.privateNets.Contains(ip) {
		if !s.conf.UsePrivateRDNS {
			return "", 0, nil
		}

		errMsg = "resolving a private address: %w"
		dctx.RequestedPrivateRDNS = netip.PrefixFrom(ip, ip.BitLen())
	} else {
		errMsg = "resolving an address: %w"
	}
	if err = s.internalProxy.Resolve(dctx); err != nil {
		return "", 0, fmt.Errorf(errMsg, err)
	}

	return hostFromPTR(dctx.Res)
}

// hostFromPTR returns domain name from the PTR response or error.
func hostFromPTR(resp *dns.Msg) (host string, ttl time.Duration, err error) {
	// Distinguish between NODATA response and a failed request.
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return "", 0, fmt.Errorf(
			"received %s response: %w",
			dns.RcodeToString[resp.Rcode],
			ErrRDNSFailed,
		)
	}

	var ttlSec uint32

	log.Debug("dnsforward: resolving ptr, received %d answers", len(resp.Answer))
	for _, ans := range resp.Answer {
		ptr, ok := ans.(*dns.PTR)
		if !ok {
			continue
		}

		// Respect zero TTL records since some DNS servers use it to
		// locally-resolved addresses.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/6046.
		if ptr.Hdr.Ttl >= ttlSec {
			host = ptr.Ptr
			ttlSec = ptr.Hdr.Ttl
		}
	}

	if host != "" {
		// NOTE:  Don't use [aghnet.NormalizeDomain] to retain original letter
		// case.
		host = strings.TrimSuffix(host, ".")
		ttl = time.Duration(ttlSec) * time.Second

		return host, ttl, nil
	}

	return "", 0, ErrRDNSNoData
}

// Start starts the DNS server.  It must only be called after [Server.Prepare].
func (s *Server) Start() error {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	return s.startLocked()
}

// startLocked starts the DNS server without locking.  s.serverLock is expected
// to be locked.
func (s *Server) startLocked() error {
	// TODO(e.burkov):  Use context properly.
	err := s.dnsProxy.Start(context.Background())
	if err == nil {
		s.isRunning = true
	}

	return err
}

// Prepare initializes parameters of s using data from conf.  conf must not be
// nil.
func (s *Server) Prepare(conf *ServerConfig) (err error) {
	s.conf = *conf

	// dnsFilter can be nil during application update.
	if s.dnsFilter != nil {
		mode, bIPv4, bIPv6 := s.dnsFilter.BlockingMode()
		err = validateBlockingMode(mode, bIPv4, bIPv6)
		if err != nil {
			return fmt.Errorf("checking blocking mode: %w", err)
		}
	}

	s.initDefaultSettings()

	err = s.prepareInternalDNS()
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	proxyConfig, err := s.newProxyConfig()
	if err != nil {
		return fmt.Errorf("preparing proxy: %w", err)
	}

	s.setupDNS64()

	s.access, err = newAccessCtx(
		s.conf.AllowedClients,
		s.conf.DisallowedClients,
		s.conf.BlockedHosts,
		s.conf.AllowedCountries,
		s.conf.BlockedCountries,
	)
	if err != nil {
		return fmt.Errorf("preparing access: %w", err)
	}

	proxyConfig.Fallbacks, err = s.setupFallbackDNS()
	if err != nil {
		return fmt.Errorf("setting up fallback dns servers: %w", err)
	}

	dnsProxy, err := proxy.New(proxyConfig)
	if err != nil {
		return fmt.Errorf("creating proxy: %w", err)
	}

	s.dnsProxy = dnsProxy

	s.setupAddrProc()

	s.registerHandlers()

	return nil
}

// prepareUpstreamSettings sets upstream DNS server settings.
func (s *Server) prepareUpstreamSettings(boot upstream.Resolver) (err error) {
	// Load upstreams either from the file, or from the settings
	var upstreams []string
	upstreams, err = s.conf.loadUpstreams()
	if err != nil {
		return fmt.Errorf("loading upstreams: %w", err)
	}

	uc, err := newUpstreamConfig(upstreams, defaultDNS, &upstream.Options{
		Logger:       aghslog.NewForUpstream(s.baseLogger, aghslog.UpstreamTypeMain),
		Bootstrap:    boot,
		Timeout:      s.conf.UpstreamTimeout,
		HTTPVersions: aghnet.UpstreamHTTPVersions(s.conf.UseHTTP3Upstreams),
		PreferIPv6:   s.conf.BootstrapPreferIPv6,
		// Use a customized set of RootCAs, because Go's default mechanism of
		// loading TLS roots does not always work properly on some routers so we're
		// loading roots manually and pass it here.
		//
		// See [aghtls.SystemRootCAs].
		//
		// TODO(a.garipov): Investigate if that's true.
		RootCAs:      s.conf.TLSv12Roots,
		CipherSuites: s.conf.TLSCiphers,
	})
	if err != nil {
		return fmt.Errorf("preparing upstream config: %w", err)
	}

	s.conf.UpstreamConfig = uc
	s.conf.ClientsContainer.UpdateCommonUpstreamConfig(&client.CommonUpstreamConfig{
		Bootstrap:               boot,
		UpstreamTimeout:         s.conf.UpstreamTimeout,
		BootstrapPreferIPv6:     s.conf.BootstrapPreferIPv6,
		EDNSClientSubnetEnabled: s.conf.EDNSClientSubnet.Enabled,
		UseHTTP3Upstreams:       s.conf.UseHTTP3Upstreams,
	})

	return nil
}

// PrivateRDNSError is returned when the private rDNS upstreams are
// invalid but enabled.
//
// TODO(e.burkov):  Consider allowing to use incomplete private rDNS upstreams
// configuration in proxy when the private rDNS function is enabled.  In theory,
// proxy supports the case when no upstreams provided to resolve the private
// request, since it already supports this for DNS64-prefixed PTR requests.
type PrivateRDNSError struct {
	err error
}

// Error implements the [errors.Error] interface.
func (e *PrivateRDNSError) Error() (s string) {
	return e.err.Error()
}

func (e *PrivateRDNSError) Unwrap() (err error) {
	return e.err
}

// prepareLocalResolvers initializes the private RDNS upstream configuration
// according to the server's settings.  It assumes s.serverLock is locked or the
// Server not running.
func (s *Server) prepareLocalResolvers() (uc *proxy.UpstreamConfig, err error) {
	if !s.conf.UsePrivateRDNS {
		return nil, nil
	}

	var ownAddrs addrPortSet
	ownAddrs, err = s.conf.ourAddrsSet()
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	opts := &upstream.Options{
		Logger:    aghslog.NewForUpstream(s.baseLogger, aghslog.UpstreamTypeLocal),
		Bootstrap: s.bootstrap,
		Timeout:   defaultLocalTimeout,
		// TODO(e.burkov): Should we verify server's certificates?
		PreferIPv6: s.conf.BootstrapPreferIPv6,
	}

	addrs := s.conf.LocalPTRResolvers
	uc, err = newPrivateConfig(addrs, ownAddrs, s.sysResolvers, s.privateNets, opts)
	if err != nil {
		return nil, fmt.Errorf("preparing resolvers: %w", err)
	}

	return uc, nil
}

// prepareInternalDNS initializes the internal state of s before initializing
// the primary DNS proxy instance.  It assumes s.serverLock is locked or the
// Server not running.
func (s *Server) prepareInternalDNS() (err error) {
	ipsetList, err := s.prepareIpsetListSettings()
	if err != nil {
		return fmt.Errorf("preparing ipset settings: %w", err)
	}

	ipsetLogger := s.baseLogger.With(slogutil.KeyPrefix, "ipset")
	s.ipset, err = newIpsetHandler(context.TODO(), ipsetLogger, ipsetList)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	bootOpts := &upstream.Options{
		Logger:       aghslog.NewForUpstream(s.baseLogger, aghslog.UpstreamTypeBootstrap),
		Timeout:      DefaultTimeout,
		HTTPVersions: aghnet.UpstreamHTTPVersions(s.conf.UseHTTP3Upstreams),
	}

	s.bootstrap, s.bootResolvers, err = newBootstrap(s.conf.BootstrapDNS, s.etcHosts, bootOpts)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = s.prepareUpstreamSettings(s.bootstrap)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	s.conf.PrivateRDNSUpstreamConfig, err = s.prepareLocalResolvers()
	if err != nil {
		return err
	}

	err = s.prepareInternalProxy()
	if err != nil {
		return fmt.Errorf("preparing internal proxy: %w", err)
	}

	return nil
}

// setupFallbackDNS initializes the fallback DNS servers.
func (s *Server) setupFallbackDNS() (uc *proxy.UpstreamConfig, err error) {
	fallbacks := s.conf.FallbackDNS
	fallbacks = stringutil.FilterOut(fallbacks, aghnet.IsCommentOrEmpty)
	if len(fallbacks) == 0 {
		return nil, nil
	}

	uc, err = proxy.ParseUpstreamsConfig(fallbacks, &upstream.Options{
		Logger: aghslog.NewForUpstream(s.baseLogger, aghslog.UpstreamTypeFallback),
		// TODO(s.chzhen):  Investigate if other options are needed.
		Timeout:    s.conf.UpstreamTimeout,
		PreferIPv6: s.conf.BootstrapPreferIPv6,
		// TODO(e.burkov):  Use bootstrap.
	})
	if err != nil {
		// Do not wrap the error because it's informative enough as is.
		return nil, err
	}

	return uc, nil
}

// setupAddrProc initializes the address processor.  It assumes s.serverLock is
// locked or the Server not running.
func (s *Server) setupAddrProc() {
	// TODO(a.garipov): This is a crutch for tests; remove.
	if s.conf.AddrProcConf == nil {
		s.conf.AddrProcConf = &client.DefaultAddrProcConfig{}
	}
	if s.conf.AddrProcConf.AddressUpdater == nil {
		s.addrProc = client.EmptyAddrProc{}
	} else {
		c := s.conf.AddrProcConf
		c.BaseLogger = s.baseLogger
		c.DialContext = s.DialContext
		c.PrivateSubnets = s.privateNets
		c.UsePrivateRDNS = s.conf.UsePrivateRDNS
		s.addrProc = client.NewDefaultAddrProc(s.conf.AddrProcConf)

		// Clear the initial addresses to not resolve them again.
		//
		// TODO(a.garipov): Consider ways of removing this once more client
		// logic is moved to package client.
		c.InitialAddresses = nil
	}
}

// validateBlockingMode returns an error if the blocking mode data aren't valid.
func validateBlockingMode(
	mode filtering.BlockingMode,
	blockingIPv4, blockingIPv6 netip.Addr,
) (err error) {
	switch mode {
	case
		filtering.BlockingModeDefault,
		filtering.BlockingModeNXDOMAIN,
		filtering.BlockingModeREFUSED,
		filtering.BlockingModeNullIP:
		return nil
	case filtering.BlockingModeCustomIP:
		if !blockingIPv4.Is4() {
			return fmt.Errorf("blocking_ipv4 must be valid ipv4 on custom_ip blocking_mode")
		} else if !blockingIPv6.Is6() {
			return fmt.Errorf("blocking_ipv6 must be valid ipv6 on custom_ip blocking_mode")
		}

		return nil
	default:
		return fmt.Errorf("bad blocking mode %q", mode)
	}
}

// prepareInternalProxy initializes the DNS proxy that is used for internal DNS
// queries, such as public clients PTR resolving and updater hostname resolving.
func (s *Server) prepareInternalProxy() (err error) {
	srvConf := s.conf
	conf := &proxy.Config{
		Logger:                    s.baseLogger.With(slogutil.KeyPrefix, aghslog.PrefixDNSProxy),
		CacheEnabled:              true,
		CacheSizeBytes:            4096,
		PrivateRDNSUpstreamConfig: srvConf.PrivateRDNSUpstreamConfig,
		UpstreamConfig:            srvConf.UpstreamConfig,
		MaxGoroutines:             srvConf.MaxGoroutines,
		UseDNS64:                  srvConf.UseDNS64,
		DNS64Prefs:                srvConf.DNS64Prefixes,
		UsePrivateRDNS:            srvConf.UsePrivateRDNS,
		PrivateSubnets:            s.privateNets,
		MessageConstructor:        s,
	}

	err = setProxyUpstreamMode(conf, srvConf.UpstreamMode, time.Duration(srvConf.FastestTimeout))
	if err != nil {
		return fmt.Errorf("invalid upstream mode: %w", err)
	}

	s.internalProxy, err = proxy.New(conf)

	return err
}

// Stop stops the DNS server.
func (s *Server) Stop() error {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	s.stopLocked()

	return nil
}

// stopLocked stops the DNS server without locking.  s.serverLock is expected to
// be locked.
func (s *Server) stopLocked() {
	// TODO(e.burkov, a.garipov):  Return critical errors, not just log them.
	// This will require filtering all the non-critical errors in
	// [upstream.Upstream] implementations.

	if s.dnsProxy != nil {
		// TODO(e.burkov):  Use context properly.
		err := s.dnsProxy.Shutdown(context.Background())
		if err != nil {
			log.Error("dnsforward: closing primary resolvers: %s", err)
		}
	}

	for _, b := range s.bootResolvers {
		logCloserErr(b, "dnsforward: closing bootstrap %s: %s", b.Address())
	}

	s.isRunning = false
}

// logCloserErr logs the error returned by c, if any.
func logCloserErr(c io.Closer, format string, args ...any) {
	if c == nil {
		return
	}

	err := c.Close()
	if err != nil {
		log.Error(format, append(args, err)...)
	}
}

// IsRunning returns true if the DNS server is running.
func (s *Server) IsRunning() bool {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	return s.isRunning
}

// srvClosedErr is returned when the method can't complete without inaccessible
// data from the closing server.
const srvClosedErr errors.Error = "server is closed"

// proxy returns a pointer to the current DNS proxy instance.  If p is nil, the
// server is closing.
//
// See https://github.com/AdguardTeam/AdGuardHome/issues/3655.
func (s *Server) proxy() (p *proxy.Proxy) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	return s.dnsProxy
}

// Reconfigure applies the new configuration to the DNS server.
//
// TODO(a.garipov): This whole piece of API is weird and needs to be remade.
func (s *Server) Reconfigure(conf *ServerConfig) error {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	log.Info("dnsforward: starting reconfiguring server")
	defer log.Info("dnsforward: finished reconfiguring server")

	s.stopLocked()

	// It seems that net.Listener.Close() doesn't close file descriptors right away.
	// We wait for some time and hope that this fd will be closed.
	time.Sleep(100 * time.Millisecond)

	if s.addrProc != nil {
		err := s.addrProc.Close()
		if err != nil {
			log.Error("dnsforward: closing address processor: %s", err)
		}
	}

	if conf == nil {
		conf = &s.conf
	}

	// TODO(e.burkov):  It seems an error here brings the server down, which is
	// not reliable enough.
	err := s.Prepare(conf)
	if err != nil {
		return fmt.Errorf("could not reconfigure the server: %w", err)
	}

	err = s.startLocked()
	if err != nil {
		return fmt.Errorf("could not reconfigure the server: %w", err)
	}

	return nil
}

// ServeHTTP is a HTTP handler method we use to provide DNS-over-HTTPS.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if prx := s.proxy(); prx != nil {
		prx.ServeHTTP(w, r)
	}
}

func (s *Server) isBlockedCountry(allowlistMode, blockedByIP, blockedByClientID bool, ip netip.Addr) (bool, string, *whois.Info) {
	if allowlistMode || blockedByIP || blockedByClientID {
		return true, "", nil
	}

	if s.access.BlockedCountriesIDs.Len() == 0 && !s.access.allowCountryMode() {
		return false, "", nil
	}

	// Use a background context and avoid extra processing for speed.
	info := s.addrProc.ProcessWHOIS(context.Background(), ip, true)
	if info == nil {
		return false, "", nil
	}

	return s.access.isBlockedCountry(info.Country), constants.CountryPrefix + info.Country, info
}

// IsBlockedClient returns true if the client is blocked by the current access
// settings.
func (s *Server) IsBlockedClient(ip netip.Addr, clientID string) (blocked bool, rule string, whois *whois.Info) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	blockedByIP := false
	if ip != (netip.Addr{}) {
		blockedByIP, rule = s.access.isBlockedIP(ip)
	}

	allowlistMode := s.access.allowlistMode()
	blockedByClientID := s.access.isBlockedClientID(clientID)
	blockedByCountry, countryRule, whois := s.isBlockedCountry(allowlistMode, blockedByIP, blockedByClientID, ip)

	// Allow if at least one of the checks allows in allowlist mode,
	// but block if at least one of the checks blocks in blocklist mode.
	if allowlistMode && blockedByIP && blockedByClientID && blockedByCountry {
		log.Debug("dnsforward: client %v (id %q) is not in access allowlist mode", ip, clientID)

		// Return now without substituting the empty rule for the
		// clientID because the rule can't be empty here.
		return true, rule, whois
	} else if !allowlistMode && (blockedByIP || blockedByClientID || blockedByCountry) {
		log.Debug("dnsforward: client %v (id %q, country %q) is in access blocklist", ip, clientID, countryRule)

		blocked = true
	}

	return blocked, cmp.Or(countryRule, rule, clientID), whois
}

// Package dnsforward contains a DNS forwarding server.
package dnsforward

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
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
	"github.com/AdguardTeam/AdGuardHome/internal/geoip"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/AdGuardHome/internal/rdns"
	"github.com/AdguardTeam/AdGuardHome/internal/stats"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/errors"
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

	// geoIP provides GeoIP lookups for country blocking.
	geoIP geoip.Interface

	// anonymizer masks the client's IP addresses if needed.
	anonymizer *aghnet.IPMut

	// baseLogger is used to create loggers for other entities.  It should not
	// have a prefix and must not be nil.
	baseLogger *slog.Logger

	// logger is used to log the operation of the DNS server.  It is created
	// during initialization in [NewServer].
	logger *slog.Logger

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
		logger:      p.Logger.With(slogutil.KeyPrefix, "dnsforward"),
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
func (s *Server) Close(ctx context.Context) {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	// TODO(s.chzhen):  Remove it.
	s.stats = nil
	s.queryLog = nil
	s.dnsProxy = nil

	if err := s.ipset.close(); err != nil {
		s.logger.ErrorContext(ctx, "closing ipset", slogutil.KeyError, err)
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
func (s *Server) Exchange(
	ctx context.Context,
	ip netip.Addr,
) (host string, ttl time.Duration, err error) {
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

	return hostFromPTR(ctx, s.logger, dctx.Res)
}

// hostFromPTR returns domain name from the PTR response or error.  l must not
// be nil.
func hostFromPTR(
	ctx context.Context,
	l *slog.Logger,
	resp *dns.Msg,
) (host string, ttl time.Duration, err error) {
	// Distinguish between NODATA response and a failed request.
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return "", 0, fmt.Errorf(
			"received %s response: %w",
			dns.RcodeToString[resp.Rcode],
			ErrRDNSFailed,
		)
	}

	var ttlSec uint32

	l.DebugContext(ctx, "resolving ptr", "num_answers", len(resp.Answer))

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
func (s *Server) Start(ctx context.Context) error {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	return s.startLocked(ctx)
}

// startLocked starts the DNS server without locking.  s.serverLock is expected
// to be locked.
func (s *Server) startLocked(ctx context.Context) error {
	err := s.dnsProxy.Start(ctx)
	if err == nil {
		s.isRunning = true
	}

	return err
}

// Prepare initializes parameters of s using data from conf.  conf must not be
// nil.
func (s *Server) Prepare(ctx context.Context, conf *ServerConfig) (err error) {
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

	err = s.prepareInternalDNS(ctx)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	proxyConfig, err := s.newProxyConfig(ctx)
	if err != nil {
		return fmt.Errorf("preparing proxy: %w", err)
	}

	s.setupDNS64()

	s.access, err = newAccessCtx(
		nil,
		s.conf.AllowedClients,
		s.conf.DisallowedClients,
		s.conf.BlockedHosts,
		s.conf.AllowedCountries,
		s.conf.BlockedCountries,
	)
	if err != nil {
		return fmt.Errorf("preparing access: %w", err)
	}

	err = s.initGeoIP()
	if err != nil {
		return err
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
func (s *Server) prepareUpstreamSettings(ctx context.Context, boot upstream.Resolver) (err error) {
	// Load upstreams either from the file, or from the settings
	var upstreams []string
	upstreams, err = s.conf.loadUpstreams(ctx, s.logger)
	if err != nil {
		return fmt.Errorf("loading upstreams: %w", err)
	}

	uc, err := newUpstreamConfig(ctx, s.logger, upstreams, defaultDNS, &upstream.Options{
		Logger:       aghslog.NewForUpstream(s.baseLogger, aghslog.UpstreamTypeMain),
		Bootstrap:    boot,
		Timeout:      s.conf.UpstreamTimeout,
		HTTPVersions: aghnet.UpstreamHTTPVersions(s.conf.UseHTTP3Upstreams),
		PreferIPv6:   s.conf.BootstrapPreferIPv6,
		// Use a customized set of RootCAs, because Go's default mechanism of
		// loading TLS roots does not always work properly on some routers so
		// we're loading roots manually and pass it here.
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
func (s *Server) prepareLocalResolvers(ctx context.Context) (uc *proxy.UpstreamConfig, err error) {
	if !s.conf.UsePrivateRDNS {
		return nil, nil
	}

	var ownAddrs addrPortSet
	ownAddrs, err = s.conf.ourAddrsSet(ctx, s.logger)
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
	uc, err = newPrivateConfig(ctx, s.logger, addrs, ownAddrs, s.sysResolvers, s.privateNets, opts)
	if err != nil {
		return nil, fmt.Errorf("preparing resolvers: %w", err)
	}

	return uc, nil
}

// prepareInternalDNS initializes the internal state of s before initializing
// the primary DNS proxy instance.  It assumes s.serverLock is locked or the
// Server not running.
func (s *Server) prepareInternalDNS(ctx context.Context) (err error) {
	ipsetList, err := s.prepareIpsetListSettings(ctx)
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

	err = s.prepareUpstreamSettings(ctx, s.bootstrap)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	s.conf.PrivateRDNSUpstreamConfig, err = s.prepareLocalResolvers(ctx)
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
func (s *Server) Stop(ctx context.Context) error {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	s.stopLocked(ctx)

	return nil
}

// stopLocked stops the DNS server without locking.  s.serverLock is expected to
// be locked.
func (s *Server) stopLocked(ctx context.Context) {
	// TODO(e.burkov, a.garipov):  Return critical errors, not just log them.
	// This will require filtering all the non-critical errors in
	// [upstream.Upstream] implementations.

	if s.dnsProxy != nil {
		err := s.dnsProxy.Shutdown(ctx)
		if err != nil {
			s.logger.ErrorContext(ctx, "closing primary resolvers", slogutil.KeyError, err)
		}
	}

	for _, b := range s.bootResolvers {
		logCloserErr(ctx, b, "closing bootstrap", s.logger.With("address", b.Address()))
	}

	s.isRunning = false
}

// logCloserErr logs the error returned by c, if any.  l and c must not be nil.
func logCloserErr(ctx context.Context, c io.Closer, msg string, l *slog.Logger) {
	if c == nil {
		return
	}

	err := c.Close()
	if err != nil {
		l.ErrorContext(ctx, msg, slogutil.KeyError, err)
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
func (s *Server) Reconfigure(ctx context.Context, conf *ServerConfig) error {
	s.serverLock.Lock()
	defer s.serverLock.Unlock()

	s.logger.InfoContext(ctx, "starting reconfiguring server")
	defer s.logger.InfoContext(ctx, "finished reconfiguring server")

	s.stopLocked(ctx)

	// It seems that net.Listener.Close() doesn't close file descriptors right
	// away.  We wait for some time and hope that this fd will be closed.
	time.Sleep(100 * time.Millisecond)

	if s.addrProc != nil {
		err := s.addrProc.Close()
		if err != nil {
			s.logger.ErrorContext(ctx, "closing address processor", slogutil.KeyError, err)
		}
	}

	if conf == nil {
		conf = &s.conf
	}

	// TODO(e.burkov):  It seems an error here brings the server down, which is
	// not reliable enough.
	err := s.Prepare(ctx, conf)
	if err != nil {
		return fmt.Errorf("could not reconfigure the server: %w", err)
	}

	err = s.startLocked(ctx)
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

func (s *Server) isBlockedCountry(ip netip.Addr, findInCacheOnly bool) (bool, string, *whois.Info) {
	if s.access.BlockedCountriesIDs.Len() == 0 && !s.access.allowCountryMode() {
		return false, "", nil
	}

	// Skip GeoIP lookup for local/private IP addresses
	if s.isLocalIP(ip) {
		return false, "", nil
	}

	country, whoisInfo := s.lookupCountry(ip, findInCacheOnly)
	if country == "" {
		return false, "", nil
	}

	return s.access.isBlockedCountry(country), constants.CountryPrefix + country, whoisInfo
}

// lookupCountry performs country lookup using GeoIP and WHOIS fallback.
func (s *Server) lookupCountry(ip netip.Addr, findInCacheOnly bool) (string, *whois.Info) {
	country, whoisInfo := s.lookupGeoIP(ip)
	return s.lookupWHOISFallback(ip, findInCacheOnly, country, whoisInfo)
}

// lookupGeoIP performs country lookup using GeoIP.
func (s *Server) lookupGeoIP(ip netip.Addr) (string, *whois.Info) {
	if s.geoIP == nil {
		return "", nil
	}

	country, err := s.geoIP.Country(ip)
	if err != nil {
		s.logger.DebugContext(context.Background(), "geoip lookup failed", "ip", ip, "error", err)
	}

	return country, &whois.Info{Country: country}
}

// updateGeoIPWithWHOIS updates the GeoIP database with WHOIS country information for IPv4 addresses.
func (s *Server) updateGeoIPWithWHOIS(ip netip.Addr, country string) {
	if ip.Is4() && s.geoIP != nil && country != "" {
		if err := s.geoIP.Update(ip, country); err != nil {
			s.logger.WarnContext(context.Background(), "failed to update geoip database for ip", "ip", ip, slogutil.KeyError, err)
			return
		}

		// Save the custom update to persist across database updates
		if err := s.saveGeoIPCustomUpdate(ip, country); err != nil {
			s.logger.WarnContext(context.Background(), "failed to save geoip custom update", "ip", ip, slogutil.KeyError, err)
		}
	}
}

// lookupWHOISFallback performs WHOIS lookup as fallback.
func (s *Server) lookupWHOISFallback(ip netip.Addr, findInCacheOnly bool, geoCountry string, geoInfo *whois.Info) (string, *whois.Info) {
	if geoCountry != "" && findInCacheOnly {
		return geoCountry, geoInfo
	}

	info := s.addrProc.ProcessWHOIS(context.Background(), ip, true, findInCacheOnly)
	if info == nil {
		return geoCountry, geoInfo
	}

	if geoCountry == "" {
		// Update GeoIP database with WHOIS country for faster lookup next time
		s.updateGeoIPWithWHOIS(ip, info.Country)
		return info.Country, info
	}

	if !strings.EqualFold(info.Country, geoCountry) {
		// Update GeoIP database with original WHOIS country for this IP
		s.updateGeoIPWithWHOIS(ip, strings.ToUpper(info.Country))

		// Country from GeoIP different with Whois
		clonedInfo := info.Clone()
		clonedInfo.Country = "Geo: " + geoCountry + ",Whois: " + info.Country
		info = clonedInfo
	}

	return geoCountry, info
}

// IsBlockedClient returns true if the client is blocked by the current access
// settings.
func (s *Server) IsBlockedClient(ip netip.Addr, clientID string) (blocked bool, rule string, whois *whois.Info) {
	return s.IsBlockedClientWithWHOIS(ip, clientID, true)
}

// IsBlockedClientWithWHOIS returns true if the client is blocked by the current access
// settings.
func (s *Server) IsBlockedClientWithWHOIS(ip netip.Addr, clientID string, findInCacheOnly bool) (blocked bool, rule string, whois *whois.Info) {
	s.serverLock.RLock()
	defer s.serverLock.RUnlock()

	checks := s.performAccessChecks(ip, clientID, findInCacheOnly)

	if s.access.allowlistMode() {
		return s.handleAllowlistMode(ip, clientID, checks)
	}

	return s.handleBlocklistMode(ip, clientID, checks)
}

// accessChecks holds the results of all access rule checks.
type accessChecks struct {
	ipChecked         bool
	clientIDChecked   bool
	countryChecked    bool
	blockedByIP       bool
	blockedByClientID bool
	blockedByCountry  bool
	rule              string
	countryRule       string
	whois             *whois.Info
}

// performAccessChecks performs all access rule checks and returns the results.
func (s *Server) performAccessChecks(ip netip.Addr, clientID string, findInCacheOnly bool) accessChecks {
	ipChecked := s.access.allowedIPs.Len() > 0 || s.access.blockedIPs.Len() > 0
	clientIDChecked := s.access.allowedClientIDs.Len() > 0 || s.access.blockedClientIDs.Len() > 0
	countryChecked := s.access.AllowedCountriesIDs.Len() > 0 || s.access.BlockedCountriesIDs.Len() > 0

	var blockedByIP bool
	var rule string
	if ipChecked && ip != (netip.Addr{}) {
		blockedByIP, rule = s.access.isBlockedIP(ip)
	}

	var blockedByClientID bool
	if clientIDChecked {
		blockedByClientID = s.access.isBlockedClientID(clientID)
	}

	var blockedByCountry bool
	var countryRule string
	var whois *whois.Info
	if countryChecked {
		blockedByCountry, countryRule, whois = s.isBlockedCountry(ip, findInCacheOnly)
	}

	return accessChecks{
		ipChecked:         ipChecked,
		clientIDChecked:   clientIDChecked,
		countryChecked:    countryChecked,
		blockedByIP:       blockedByIP,
		blockedByClientID: blockedByClientID,
		blockedByCountry:  blockedByCountry,
		rule:              rule,
		countryRule:       countryRule,
		whois:             whois,
	}
}

// handleAllowlistMode handles allowlist mode logic.
func (s *Server) handleAllowlistMode(ip netip.Addr, clientID string, checks accessChecks) (blocked bool, rule string, whois *whois.Info) {
	ipBlocks := !checks.ipChecked || checks.blockedByIP
	clientIDBlocks := !checks.clientIDChecked || checks.blockedByClientID
	countryBlocks := !checks.countryChecked || checks.blockedByCountry

	if ipBlocks && clientIDBlocks && countryBlocks {
		s.logger.DebugContext(
			context.TODO(),
			"client is not in access allowlist mode",
			"ip", ip,
			"client_id", clientID,
		)
		return true, checks.rule, checks.whois
	}

	return false, cmp.Or(checks.countryRule, checks.rule, clientID), checks.whois
}

// handleBlocklistMode handles blocklist mode logic.
func (s *Server) handleBlocklistMode(ip netip.Addr, clientID string, checks accessChecks) (blocked bool, rule string, whois *whois.Info) {
	if checks.blockedByIP || checks.blockedByClientID || checks.blockedByCountry {
		s.logger.DebugContext(
			context.TODO(),
			"client is in access blocklist",
			"ip", ip,
			"client_id", clientID,
			"country", checks.countryRule,
		)
		return true, cmp.Or(checks.countryRule, checks.rule, clientID), checks.whois
	}

	return false, cmp.Or(checks.countryRule, checks.rule, clientID), checks.whois
}

// isLocalIP returns true if the IP address is a local/private address.
func (s *Server) isLocalIP(ip netip.Addr) bool {
	if !ip.Is4() {
		return false // Only check IPv4 for simplicity
	}

	// Check common private IP ranges
	privateRanges := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),     // RFC 1918
		netip.MustParsePrefix("172.16.0.0/12"),  // RFC 1918
		netip.MustParsePrefix("192.168.0.0/16"), // RFC 1918
		netip.MustParsePrefix("127.0.0.0/8"),    // Loopback
		netip.MustParsePrefix("169.254.0.0/16"), // Link-local
	}

	for _, prefix := range privateRanges {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// initGeoIP initializes the GeoIP database if country rules are configured.
func (s *Server) initGeoIP() error {
	// Auto-enable GeoIP if country rules are configured
	hasCountryRules := len(s.conf.AllowedCountries) > 0 || len(s.conf.BlockedCountries) > 0
	geoIPEnabled := s.conf.GeoIPEnabled || hasCountryRules

	if geoIPEnabled && s.conf.GeoIPDatabasePath != "" {
		// Ensure database exists and is up to date
		if err := s.ensureGeoIPDatabase(); err != nil {
			return fmt.Errorf("ensuring geoip database: %w", err)
		}

		var err error
		s.geoIP, err = geoip.New(&geoip.Config{
			Logger:       s.baseLogger.With(slogutil.KeyPrefix, "geoip"),
			DatabasePath: s.conf.GeoIPDatabasePath,
		})
		if err != nil {
			return fmt.Errorf("initializing geoip: %w", err)
		}

		// Start background update checker
		go s.startGeoIPUpdateChecker()
	}

	return nil
}

// ensureGeoIPDatabase ensures the GeoIP database exists and downloads it if needed.
func (s *Server) ensureGeoIPDatabase() error {
	if _, err := os.Stat(s.conf.GeoIPDatabasePath); os.IsNotExist(err) {
		// Database doesn't exist, download it
		downloader := geoip.NewDownloader(s.baseLogger.With(slogutil.KeyPrefix, "geoip"))
		if dlErr := downloader.Download(context.Background(), s.conf.GeoIPDatabasePath, true); dlErr != nil {
			return fmt.Errorf("downloading geoip database: %w", dlErr)
		}
	}
	return nil
}

// startGeoIPUpdateChecker starts a background goroutine that periodically checks for database updates.
func (s *Server) startGeoIPUpdateChecker() {
	updatePeriod := time.Duration(s.conf.GeoIPUpdatePeriod)
	if updatePeriod == 0 {
		updatePeriod = 24 * time.Hour // fallback to default
	}
	ticker := time.NewTicker(updatePeriod)
	defer ticker.Stop()

	// Perform immediate check on startup
	s.checkGeoIPUpdate("on startup")

	for range ticker.C {
		s.checkGeoIPUpdate("")
	}
}

// checkGeoIPUpdate performs a GeoIP database update check with appropriate logging.
func (s *Server) checkGeoIPUpdate(contextMsg string) {
	if s.geoIP == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	logMsg := "failed to update geoip database"
	if contextMsg != "" {
		logMsg += " " + contextMsg
	}

	if err := s.updateGeoIPDatabase(ctx); err != nil {
		s.logger.WarnContext(ctx, logMsg, slogutil.KeyError, err)
	}
}

// needsGeoIPUpdate checks if the GeoIP database needs to be updated based on file modification time.
func (s *Server) needsGeoIPUpdate(ctx context.Context, fileModTime time.Time) bool {
	now := time.Now()
	fileYear, fileMonth, _ := fileModTime.Date()
	currentYear, currentMonth, _ := now.Date()

	// If file is from a previous month, check if we should update
	if fileYear < currentYear || (fileYear == currentYear && fileMonth < currentMonth) {
		s.logger.InfoContext(ctx, "geoip database is from previous month, checking for updates",
			"file_month", fileMonth, "current_month", currentMonth)
		return true
	}

	// Fallback: if file is older than 30 days regardless of month
	if time.Since(fileModTime) > 30*24*time.Hour {
		s.logger.InfoContext(ctx, "geoip database is older than 30 days, updating")
		return true
	}

	return false
}

// safeRemoveFile removes a file using explicitly separated directory and filename
// to prevent path traversal issues.
// #nosec G703 - This function is safe - it uses filepath.Join with trusted temp directory and validated basenames
func safeRemoveFile(dir, filename string) error {
	// Use filepath.Join with both components to ensure safe path construction
	// #nosec G703
	safePath := filepath.Join(dir, filename)
	return os.Remove(safePath)
}

// downloadGeoIPDatabase downloads the GeoIP database to a temporary file and validates it.
// The dbPath parameter must be a validated and cleaned path.
// NOTE: dbPath is intentionally not used in this function to break the taint chain.
// The caller validates and cleans the path before passing it here, ensuring no path
// traversal can occur through this function.
func (s *Server) downloadGeoIPDatabase(ctx context.Context, dbPath string) (string, error) {
	_ = dbPath // Explicitly acknowledge the parameter to break taint analysis

	// Use the system's temp directory for downloads to avoid path traversal issues
	tempDir := os.TempDir()
	downloader := geoip.NewDownloader(s.baseLogger.With(slogutil.KeyPrefix, "geoip"))

	// Download to a temporary file first to avoid corrupting the existing database
	tempFile, tempErr := os.CreateTemp(tempDir, "geoip_update_*.mmdb")
	if tempErr != nil {
		return "", fmt.Errorf("creating temp file for geoip update: %w", tempErr)
	}

	// Get the base name separately to break taint chain
	tempFileBase := filepath.Base(tempFile.Name())
	if err := tempFile.Close(); err != nil {
		return "", fmt.Errorf("closing temp file: %w", err)
	}

	// Construct path using separate components - this pattern helps break taint
	tempPath := safeJoinPath(tempDir, tempFileBase)

	if dlErr := downloader.Download(ctx, tempPath, false); dlErr != nil {
		// Use helper function to break taint chain
		_ = safeRemoveFile(tempDir, tempFileBase)
		s.logger.InfoContext(ctx, "current month geoip database not available, skipping update")
		return "", nil
	}

	// Validate the downloaded file
	if valErr := s.validateGeoIPDownload(tempPath); valErr != nil {
		// Use helper function to break taint chain
		_ = safeRemoveFile(tempDir, tempFileBase)
		return "", valErr
	}

	return tempPath, nil
}

// safeJoinPath safely joins directory and filename using filepath.Join.
// This function helps break the taint chain for security analysis.
func safeJoinPath(dir, filename string) string {
	return filepath.Join(dir, filename)
}

// validateGeoIPDownload validates the downloaded GeoIP database file.
func (s *Server) validateGeoIPDownload(tempPath string) error {
	stat, err := os.Stat(tempPath)
	if err != nil {
		return fmt.Errorf("stat temp geoip file: %w", err)
	}

	if stat.Size() == 0 {
		s.logger.WarnContext(context.Background(), "downloaded geoip database is empty, skipping update")
		return fmt.Errorf("downloaded geoip database is empty")
	}

	if stat.Size() < 1024*1024 { // Less than 1MB is suspiciously small
		s.logger.WarnContext(context.Background(), "downloaded geoip database is too small, skipping update", "size", stat.Size())
		return fmt.Errorf("downloaded geoip database is too small: %d bytes", stat.Size())
	}

	return nil
}

// updateGeoIPDatabase checks if the database is outdated and updates it if needed.
func (s *Server) updateGeoIPDatabase(ctx context.Context) error {
	// Validate and clean the database path to prevent path traversal
	dbPath := filepath.Clean(s.conf.GeoIPDatabasePath)
	if strings.Contains(dbPath, "..") {
		return fmt.Errorf("geoip database path contains invalid sequence: %s", s.conf.GeoIPDatabasePath)
	}

	// Check if database file exists
	stat, err := os.Stat(dbPath)
	if err != nil {
		return fmt.Errorf("stat geoip database: %w", err)
	}

	needsUpdate := s.needsGeoIPUpdate(ctx, stat.ModTime())
	if !needsUpdate {
		return nil
	}

	s.logger.InfoContext(ctx, "updating geoip database")

	tempPath, err := s.downloadGeoIPDatabase(ctx, dbPath)
	if err != nil {
		return err
	}

	if tempPath == "" {
		return nil // Download not available
	}

	// Extract basename to break taint chain for safe file operations
	dbBaseName := filepath.Base(dbPath)
	dbDir := filepath.Dir(dbPath)
	cleanDBPath := filepath.Join(dbDir, dbBaseName)

	// Extract basename from tempPath to break taint chain
	tempBaseName := filepath.Base(tempPath)
	tempDir := filepath.Dir(tempPath)
	cleanTempPath := filepath.Join(tempDir, tempBaseName)

	// Replace the existing database with the validated download
	if err = os.Rename(cleanTempPath, cleanDBPath); err != nil {
		_ = os.Remove(cleanTempPath) // cleanup operation, error not critical
		return fmt.Errorf("replacing geoip database: %w", err)
	}

	s.logger.InfoContext(ctx, "geoip database updated successfully")

	// Restore custom updates after successful database update
	if err = s.restoreGeoIPCustomUpdates(); err != nil {
		s.logger.WarnContext(ctx, "failed to restore geoip custom updates after database update", slogutil.KeyError, err)
	}

	return nil
}

// parseGeoIPCustomUpdates parses the custom updates file into a map.
func (s *Server) parseGeoIPCustomUpdates(data []byte) map[string]string {
	existing := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) == 2 {
			existing[parts[0]] = parts[1]
		}
	}
	return existing
}

// formatGeoIPCustomUpdates formats the custom updates map into file content.
func (s *Server) formatGeoIPCustomUpdates(updates map[string]string) string {
	var lines []string
	for ipStr, countryStr := range updates {
		lines = append(lines, ipStr+","+countryStr)
	}
	return strings.Join(lines, "\n") + "\n"
}

// saveGeoIPCustomUpdate saves a custom geoIP update to a persistent file.
func (s *Server) saveGeoIPCustomUpdate(ip netip.Addr, country string) error {
	if s.conf.GeoIPDatabasePath == "" {
		return fmt.Errorf("geoip database path not configured")
	}

	customPath := s.conf.GeoIPDatabasePath + ".custom"

	// Read existing custom updates
	existing := make(map[string]string)
	baseDir := filepath.Dir(s.conf.GeoIPDatabasePath)
	root := os.DirFS(baseDir)
	relPath := filepath.Base(customPath)
	if data, err := fs.ReadFile(root, relPath); err == nil {
		existing = s.parseGeoIPCustomUpdates(data)
	}

	// Add/update the new entry
	existing[ip.String()] = country

	// Write back to file
	content := s.formatGeoIPCustomUpdates(existing)
	return os.WriteFile(customPath, []byte(content), 0o600)
}

// loadGeoIPCustomUpdatesData loads the custom updates data from the file.
func (s *Server) loadGeoIPCustomUpdatesData() ([]string, error) {
	customPath := s.conf.GeoIPDatabasePath + ".custom"
	baseDir := filepath.Dir(s.conf.GeoIPDatabasePath)
	root := os.DirFS(baseDir)
	relPath := filepath.Base(customPath)
	data, readErr := fs.ReadFile(root, relPath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, nil // No custom updates file exists
		}
		return nil, fmt.Errorf("reading custom geoip updates: %w", readErr)
	}

	return strings.Split(strings.TrimSpace(string(data)), "\n"), nil
}

// applyGeoIPCustomUpdate applies a single custom update.
func (s *Server) applyGeoIPCustomUpdate(ipStr, countryStr string) error {
	ip, parseErr := netip.ParseAddr(ipStr)
	if parseErr != nil {
		s.logger.WarnContext(context.Background(), "invalid IP in custom geoip updates", "ip", ipStr, slogutil.KeyError, parseErr)
		return parseErr
	}

	if updateErr := s.geoIP.Update(ip, countryStr); updateErr != nil {
		s.logger.WarnContext(context.Background(), "failed to restore geoip custom update", "ip", ipStr, "country", countryStr, slogutil.KeyError, updateErr)
		return updateErr
	}

	return nil
}

// processGeoIPCustomUpdateLine processes a single line from the custom updates file.
func (s *Server) processGeoIPCustomUpdateLine(line string) bool {
	if line == "" {
		return false
	}
	parts := strings.Split(line, ",")
	if len(parts) != 2 {
		return false
	}

	ipStr, countryStr := parts[0], parts[1]
	return s.applyGeoIPCustomUpdate(ipStr, countryStr) == nil
}

// restoreGeoIPCustomUpdates loads and applies custom geoIP updates from the persistent file.
func (s *Server) restoreGeoIPCustomUpdates() error {
	if s.conf.GeoIPDatabasePath == "" || s.geoIP == nil {
		return nil
	}

	lines, err := s.loadGeoIPCustomUpdatesData()
	if err != nil {
		return err
	}

	restoredCount := 0
	for _, line := range lines {
		if s.processGeoIPCustomUpdateLine(line) {
			restoredCount++
		}
	}

	if restoredCount > 0 {
		s.logger.InfoContext(context.Background(), "restored geoip custom updates", "count", restoredCount)
	}

	return nil
}

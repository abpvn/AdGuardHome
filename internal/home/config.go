package home

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/AdguardTeam/AdGuardHome/internal/aghalg"
	"github.com/AdguardTeam/AdGuardHome/internal/aghos"
	"github.com/AdguardTeam/AdGuardHome/internal/aghtls"
	"github.com/AdguardTeam/AdGuardHome/internal/configmigrate"
	"github.com/AdguardTeam/AdGuardHome/internal/dhcpd"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/AdGuardHome/internal/stats"
	"github.com/AdguardTeam/dnsproxy/fastip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/google/go-cmp/cmp"
	"github.com/google/renameio/v2/maybe"
	yaml "gopkg.in/yaml.v3"
)

const (
	// dataDir is the name of a directory under the working one to store some
	// persistent data.
	dataDir = "data"

	// userFilterDataDir is the name of the directory used to store users'
	// FS-based rule lists.
	userFilterDataDir = "userfilters"
)

// logSettings are the logging settings part of the configuration file.
type logSettings struct {
	// Enabled indicates whether logging is enabled.
	Enabled bool `yaml:"enabled"`

	// File is the path to the log file.  If empty, logs are written to stdout.
	// If "syslog", logs are written to syslog.
	File string `yaml:"file"`

	// MaxBackups is the maximum number of old log files to retain.
	//
	// NOTE: MaxAge may still cause them to get deleted.
	MaxBackups int `yaml:"max_backups"`

	// MaxSize is the maximum size of the log file before it gets rotated, in
	// megabytes.  The default value is 100 MB.
	MaxSize int `yaml:"max_size"`

	// MaxAge is the maximum duration for retaining old log files, in days.
	MaxAge int `yaml:"max_age"`

	// Compress determines, if the rotated log files should be compressed using
	// gzip.
	Compress bool `yaml:"compress"`

	// LocalTime determines, if the time used for formatting the timestamps in
	// is the computer's local time.
	LocalTime bool `yaml:"local_time"`

	// Verbose determines, if verbose (aka debug) logging is enabled.
	Verbose bool `yaml:"verbose"`
}

// osConfig contains OS-related configuration.
type osConfig struct {
	// Group is the name of the group which AdGuard Home must switch to on
	// startup.  Empty string means no switching.
	Group string `yaml:"group"`
	// User is the name of the user which AdGuard Home must switch to on
	// startup.  Empty string means no switching.
	User string `yaml:"user"`
	// RlimitNoFile is the maximum number of opened fd's per process.  Zero
	// means use the default value.
	RlimitNoFile uint64 `yaml:"rlimit_nofile"`
}

type clientsConfig struct {
	// Sources defines the set of sources to fetch the runtime clients from.
	Sources *clientSourcesConfig `yaml:"runtime_sources"`
	// Persistent are the configured clients.
	Persistent []*clientObject `yaml:"persistent"`
}

// clientSourceConfig is used to configure where the runtime clients will be
// obtained from.
type clientSourcesConfig struct {
	WHOIS     bool `yaml:"whois"`
	ARP       bool `yaml:"arp"`
	RDNS      bool `yaml:"rdns"`
	DHCP      bool `yaml:"dhcp"`
	HostsFile bool `yaml:"hosts"`
}

// configuration is loaded from YAML.
//
// Field ordering is important, YAML fields better not to be reordered, if it's
// not absolutely necessary.
type configuration struct {
	// Raw file data to avoid re-reading of configuration file
	// It's reset after config is parsed
	fileData []byte

	// HTTPConfig is the block with http conf.
	HTTPConfig httpConfig `yaml:"http"`
	// Users are the clients capable for accessing the web interface.
	Users []webUser `yaml:"users"`
	// AuthAttempts is the maximum number of failed login attempts a user
	// can do before being blocked.
	AuthAttempts uint `yaml:"auth_attempts"`
	// AuthBlockMin is the duration, in minutes, of the block of new login
	// attempts after AuthAttempts unsuccessful login attempts.
	AuthBlockMin uint `yaml:"block_auth_min"`
	// ProxyURL is the address of proxy server for the internal HTTP client.
	ProxyURL string `yaml:"http_proxy"`
	// Language is a two-letter ISO 639-1 language code.
	Language string `yaml:"language"`
	// Theme is a UI theme for current user.
	Theme Theme `yaml:"theme"`

	// TODO(a.garipov): Make DNS and the fields below pointers and validate
	// and/or reset on explicit nulling.
	DNS      dnsConfig         `yaml:"dns"`
	TLS      tlsConfigSettings `yaml:"tls"`
	QueryLog queryLogConfig    `yaml:"querylog"`
	Stats    statsConfig       `yaml:"statistics"`

	// Filters reflects the filters from [filtering.Config].  It's cloned to the
	// config used in the filtering module at the startup.  Afterwards it's
	// cloned from the filtering module back here.
	//
	// TODO(e.burkov):  Move all the filtering configuration fields into the
	// only configuration subsection covering the changes with a single
	// migration.  Also keep the blocked services in mind.
	Filters          []filtering.FilterYAML `yaml:"filters"`
	WhitelistFilters []filtering.FilterYAML `yaml:"whitelist_filters"`
	UserRules        []string               `yaml:"user_rules"`
	// Store all clients filters list to make all filters list added by clients to AGH is unique
	ClientsFilters []filtering.ClientFilterYAML `yaml:"clients_filters"`

	DHCP      *dhcpd.ServerConfig `yaml:"dhcp"`
	Filtering *filtering.Config   `yaml:"filtering"`

	// Clients contains the YAML representations of the persistent clients.
	// This field is only used for reading and writing persistent client data.
	// Keep this field sorted to ensure consistent ordering.
	Clients *clientsConfig `yaml:"clients"`

	// Log is a block with log configuration settings.
	Log logSettings `yaml:"log"`

	OSConfig *osConfig `yaml:"os"`

	sync.RWMutex `yaml:"-"`

	// SchemaVersion is the version of the configuration schema.  See
	// [configmigrate.LastSchemaVersion].
	SchemaVersion uint `yaml:"schema_version"`

	// UnsafeUseCustomUpdateIndexURL is the URL to the custom update index.
	//
	// NOTE: It's only exists for testing purposes and should not be used in
	// release.
	UnsafeUseCustomUpdateIndexURL bool `yaml:"unsafe_use_custom_update_index_url,omitempty"`
}

// httpConfig is a block with HTTP configuration params.
//
// Field ordering is important, YAML fields better not to be reordered, if it's
// not absolutely necessary.
type httpConfig struct {
	// Pprof defines the profiling HTTP handler.
	Pprof *httpPprofConfig `yaml:"pprof"`

	// Address is the address to serve the web UI on.
	Address netip.AddrPort

	// SessionTTL for a web session.
	// An active session is automatically refreshed once a day.
	SessionTTL timeutil.Duration `yaml:"session_ttl"`
}

// httpPprofConfig is the block with pprof HTTP configuration.
type httpPprofConfig struct {
	// Port for the profiling handler.
	Port uint16 `yaml:"port"`

	// Enabled defines if the profiling handler is enabled.
	Enabled bool `yaml:"enabled"`
}

// dnsConfig is a block with DNS configuration params.
//
// Field ordering is important, YAML fields better not to be reordered, if it's
// not absolutely necessary.
type dnsConfig struct {
	BindHosts []netip.Addr `yaml:"bind_hosts"`
	Port      uint16       `yaml:"port"`

	// AnonymizeClientIP defines if clients' IP addresses should be anonymized
	// in query log and statistics.
	AnonymizeClientIP bool `yaml:"anonymize_client_ip"`

	// IgnoreNoneClientLog defines only store query log of configured clients
	IgnoreNoneClientLog bool `yaml:"ignore_non_client_log"`

	// Config is the embed configuration with DNS params.
	//
	// TODO(a.garipov): Remove embed.
	dnsforward.Config `yaml:",inline"`

	// UpstreamTimeout is the timeout for querying upstream servers.
	UpstreamTimeout timeutil.Duration `yaml:"upstream_timeout"`

	// PrivateNets is the set of IP networks for which the private reverse DNS
	// resolver should be used.
	PrivateNets []netutil.Prefix `yaml:"private_networks"`

	// UsePrivateRDNS enables resolving requests containing a private IP address
	// using private reverse DNS resolvers.  See PrivateRDNSResolvers.
	//
	// TODO(e.burkov):  Rename in YAML.
	UsePrivateRDNS bool `yaml:"use_private_ptr_resolvers"`

	// PrivateRDNSResolvers is the slice of addresses to be used as upstreams
	// for private requests.  It's only used for PTR, SOA, and NS queries,
	// containing an ARPA subdomain, came from the the client with private
	// address.  The address considered private according to PrivateNets.
	//
	// If empty, the OS-provided resolvers are used for private requests.
	PrivateRDNSResolvers []string `yaml:"local_ptr_upstreams"`

	// UseDNS64 defines if DNS64 should be used for incoming requests.  Requests
	// of type PTR for addresses within the configured prefixes will be resolved
	// via [PrivateRDNSResolvers], so those should be valid and UsePrivateRDNS
	// be set to true.
	UseDNS64 bool `yaml:"use_dns64"`

	// DNS64Prefixes is the list of NAT64 prefixes to be used for DNS64.
	DNS64Prefixes []netip.Prefix `yaml:"dns64_prefixes"`

	// ServeHTTP3 defines if HTTP/3 is allowed for incoming requests.
	//
	// TODO(a.garipov): Add to the UI when HTTP/3 support is no longer
	// experimental.
	ServeHTTP3 bool `yaml:"serve_http3"`

	// UseHTTP3Upstreams defines if HTTP/3 is allowed for DNS-over-HTTPS
	// upstreams.
	//
	// TODO(a.garipov): Add to the UI when HTTP/3 support is no longer
	// experimental.
	UseHTTP3Upstreams bool `yaml:"use_http3_upstreams"`

	// ServePlainDNS defines if plain DNS is allowed for incoming requests.
	ServePlainDNS bool `yaml:"serve_plain_dns"`

	// HostsFileEnabled defines whether to use information from the system hosts
	// file to resolve queries.
	HostsFileEnabled bool `yaml:"hostsfile_enabled"`

	// PendingRequests configures duplicate requests policy.
	PendingRequests *pendingRequests `yaml:"pending_requests"`
}

// pendingRequests is a block with pending requests configuration.
type pendingRequests struct {
	// Enabled controls if duplicate requests should be sent to the upstreams
	// along with the original one.
	Enabled bool `yaml:"enabled"`
}

// tlsConfigSettings is the TLS configuration for DNS-over-TLS, DNS-over-QUIC,
// and HTTPS.  When adding new properties, update the [tlsConfigSettings.clone]
// and [tlsConfigSettings.setPrivateFieldsAndCompare] methods as necessary.
type tlsConfigSettings struct {
	// Enabled indicates whether encryption (DoT/DoH/HTTPS) is enabled.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// ServerNames is the hostname of the HTTPS/TLS server.
	ServerNames []string `yaml:"server_names" json:"server_names,omitempty"`

	// ForceHTTPS, if true, forces an HTTP to HTTPS redirect.
	ForceHTTPS bool `yaml:"force_https" json:"force_https"`

	// PortHTTPS is the HTTPS port.  If 0, HTTPS will be disabled.
	PortHTTPS uint16 `yaml:"port_https" json:"port_https,omitempty"`

	// PortDNSOverTLS is the DNS-over-TLS port.  If 0, DoT will be disabled.
	PortDNSOverTLS uint16 `yaml:"port_dns_over_tls" json:"port_dns_over_tls,omitempty"`

	// PortDNSOverQUIC is the DNS-over-QUIC port.  If 0, DoQ will be disabled.
	PortDNSOverQUIC uint16 `yaml:"port_dns_over_quic" json:"port_dns_over_quic,omitempty"`

	// PortDNSCrypt is the port for DNSCrypt requests.  If it's zero, DNSCrypt
	// is disabled.
	PortDNSCrypt uint16 `yaml:"port_dnscrypt" json:"port_dnscrypt"`

	// DNSCryptConfigFile is the path to the DNSCrypt config file.  Must be set
	// if PortDNSCrypt is not zero.
	//
	// See https://github.com/AdguardTeam/dnsproxy and
	// https://github.com/ameshkov/dnscrypt.
	DNSCryptConfigFile string `yaml:"dnscrypt_config_file" json:"dnscrypt_config_file"`

	// AllowUnencryptedDoH allows DoH queries via unencrypted HTTP (e.g. for
	// reverse proxying).
	//
	// TODO(s.chzhen):  Add this option into the Web UI.
	AllowUnencryptedDoH bool `yaml:"allow_unencrypted_doh" json:"allow_unencrypted_doh"`

	// CertificateChain is the PEM-encoded certificate chain.  Must be empty if
	// [tlsConfigSettings.CertificatePath] is provided.
	CertificateChain string `yaml:"certificate_chain" json:"certificate_chain"`

	// PrivateKey is the PEM-encoded private key.  Must be empty if
	// [tlsConfigSettings.PrivateKeyPath] is provided.
	PrivateKey string `yaml:"private_key" json:"private_key"`

	// CertificatePath is the path to the certificate file.  Must be empty if
	// [tlsConfigSettings.CertificateChain] is provided.
	CertificatePath string `yaml:"certificate_path" json:"certificate_path"`

	// PrivateKeyPath is the path to the private key file.  Must be empty if
	// [tlsConfigSettings.PrivateKey] is provided.
	PrivateKeyPath string `yaml:"private_key_path" json:"private_key_path"`

	// OverrideTLSCiphers, when set, contains the names of the cipher suites to
	// use.  If the slice is empty, the default safe suites are used.
	OverrideTLSCiphers []string `yaml:"override_tls_ciphers,omitempty" json:"-"`

	// CertificateChainData is the PEM-encoded byte data for the certificate
	// chain.
	CertificateChainData []byte `yaml:"-" json:"-"`

	// PrivateKeyData is the PEM-encoded byte data for the private key.
	PrivateKeyData []byte `yaml:"-" json:"-"`

	// StrictSNICheck controls if the connections with SNI mismatching the
	// certificate's ones should be rejected.
	StrictSNICheck bool `yaml:"strict_sni_check" json:"-"`
}

// clone returns a deep copy of c.
func (c *tlsConfigSettings) clone() (clone *tlsConfigSettings) {
	clone = &tlsConfigSettings{}
	*clone = *c

	clone.OverrideTLSCiphers = slices.Clone(c.OverrideTLSCiphers)
	clone.CertificateChainData = slices.Clone(c.CertificateChainData)
	clone.PrivateKeyData = slices.Clone(c.PrivateKeyData)

	return clone
}

// setPrivateFieldsAndCompare sets any missing properties in conf to match those
// in c and returns true if TLS configurations are equal.  conf must not be be
// nil.
// It sets the following properties because these are not accepted from the
// frontend:
//
//	[tlsConfigSettings.AllowUnencryptedDoH]
//	[tlsConfigSettings.DNSCryptConfigFile]
//	[tlsConfigSettings.OverrideTLSCiphers]
//	[tlsConfigSettings.PortDNSCrypt]
//
// The following properties are skipped as they are set by
// [tlsManager.loadTLSConfig]:
//
//	[tlsConfigSettings.CertificateChainData]
//	[tlsConfigSettings.PrivateKeyData]
func (c *tlsConfigSettings) setPrivateFieldsAndCompare(conf *tlsConfigSettings) (equal bool) {
	conf.OverrideTLSCiphers = slices.Clone(c.OverrideTLSCiphers)

	conf.DNSCryptConfigFile = c.DNSCryptConfigFile
	conf.PortDNSCrypt = c.PortDNSCrypt

	// TODO(a.garipov): Define a custom comparer.
	return cmp.Equal(c, conf)
}

type queryLogConfig struct {
	// DirPath is the custom directory for logs.  If it's empty the default
	// directory will be used.  See [homeContext.getDataDir].
	DirPath string `yaml:"dir_path"`

	// Ignored is the list of host names, which should not be written to log.
	// "." is considered to be the root domain.
	Ignored []string `yaml:"ignored"`

	// Interval is the interval for query log's files rotation.
	Interval timeutil.Duration `yaml:"interval"`

	// MemSize is the number of entries kept in memory before they are flushed
	// to disk.
	MemSize uint `yaml:"size_memory"`

	// Enabled defines if the query log is enabled.
	Enabled bool `yaml:"enabled"`

	// FileEnabled defines, if the query log is written to the file.
	FileEnabled bool `yaml:"file_enabled"`
}

type statsConfig struct {
	// DirPath is the custom directory for statistics.  If it's empty the
	// default directory is used.  See [homeContext.getDataDir].
	DirPath string `yaml:"dir_path"`

	// Ignored is the list of host names, which should not be counted.
	Ignored []string `yaml:"ignored"`

	// Interval is the retention interval for statistics.
	Interval timeutil.Duration `yaml:"interval"`

	// Enabled defines if the statistics are enabled.
	Enabled bool `yaml:"enabled"`
}

// Default block host constants.
const (
	defaultSafeBrowsingBlockHost = "standard-block.dns.adguard.com"
	defaultParentalBlockHost     = "family-block.dns.adguard.com"
)

// config is the global configuration structure.
//
// TODO(a.garipov, e.burkov): This global is awful and must be removed.
var config = &configuration{
	AuthAttempts: 5,
	AuthBlockMin: 15,
	HTTPConfig: httpConfig{
		Address:    netip.AddrPortFrom(netip.IPv4Unspecified(), 3000),
		SessionTTL: timeutil.Duration(30 * timeutil.Day),
		Pprof: &httpPprofConfig{
			Enabled: false,
			Port:    6060,
		},
	},
	DNS: dnsConfig{
		BindHosts: []netip.Addr{netip.IPv4Unspecified()},
		Port:      defaultPortDNS,
		Config: dnsforward.Config{
			Ratelimit:              20,
			RatelimitSubnetLenIPv4: 24,
			RatelimitSubnetLenIPv6: 56,
			RefuseAny:              true,
			UpstreamMode:           dnsforward.UpstreamModeLoadBalance,
			HandleDDR:              true,
			FastestTimeout:         timeutil.Duration(fastip.DefaultPingWaitTimeout),

			TrustedProxies: []netutil.Prefix{{
				Prefix: netip.MustParsePrefix("127.0.0.0/8"),
			}, {
				Prefix: netip.MustParsePrefix("::1/128"),
			}},
			CacheSize: 4 * 1024 * 1024,

			EDNSClientSubnet: &dnsforward.EDNSClientSubnet{
				CustomIP:  netip.Addr{},
				Enabled:   false,
				UseCustom: false,
			},

			// set default maximum concurrent queries to 300
			// we introduced a default limit due to this:
			// https://github.com/AdguardTeam/AdGuardHome/issues/2015#issuecomment-674041912
			// was later increased to 300 due to https://github.com/AdguardTeam/AdGuardHome/issues/2257
			MaxGoroutines: 300,
		},
		UpstreamTimeout:  timeutil.Duration(dnsforward.DefaultTimeout),
		UsePrivateRDNS:   true,
		ServePlainDNS:    true,
		HostsFileEnabled: true,
		PendingRequests: &pendingRequests{
			Enabled: true,
		},
	},
	TLS: tlsConfigSettings{
		PortHTTPS:       defaultPortHTTPS,
		PortDNSOverTLS:  defaultPortTLS, // needs to be passed through to dnsproxy
		PortDNSOverQUIC: defaultPortQUIC,
	},
	QueryLog: queryLogConfig{
		Enabled:     true,
		FileEnabled: true,
		Interval:    timeutil.Duration(90 * timeutil.Day),
		MemSize:     1000,
		Ignored:     []string{},
	},
	Stats: statsConfig{
		Enabled:  true,
		Interval: timeutil.Duration(1 * timeutil.Day),
		Ignored:  []string{},
	},
	// NOTE: Keep these parameters in sync with the one put into
	// client/src/helpers/filters/filters.ts by scripts/vetted-filters.
	//
	// TODO(a.garipov): Think of a way to make scripts/vetted-filters update
	// these as well if necessary.
	Filters: []filtering.FilterYAML{{
		Filter:  filtering.Filter{ID: 1},
		Enabled: true,
		URL:     "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
		Name:    "AdGuard DNS filter",
	}, {
		Filter:  filtering.Filter{ID: 2},
		Enabled: false,
		URL:     "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
		Name:    "AdAway Default Blocklist",
	}},
	Filtering: &filtering.Config{
		ProtectionEnabled:  true,
		BlockingMode:       filtering.BlockingModeDefault,
		BlockedResponseTTL: 10, // in seconds

		FilteringEnabled:           true,
		FiltersUpdateIntervalHours: 24,

		ParentalEnabled:     false,
		SafeBrowsingEnabled: false,

		SafeBrowsingCacheSize: 1 * 1024 * 1024,
		SafeSearchCacheSize:   1 * 1024 * 1024,
		ParentalCacheSize:     1 * 1024 * 1024,
		CacheTime:             30,

		SafeSearchConf: filtering.SafeSearchConfig{
			Enabled:    false,
			Bing:       true,
			DuckDuckGo: true,
			Ecosia:     true,
			Google:     true,
			Pixabay:    true,
			Yandex:     true,
			YouTube:    true,
		},

		BlockedServices: &filtering.BlockedServices{
			Schedule: schedule.EmptyWeekly(),
			IDs:      []string{},
		},

		ParentalBlockHost:     defaultParentalBlockHost,
		SafeBrowsingBlockHost: defaultSafeBrowsingBlockHost,
	},
	DHCP: &dhcpd.ServerConfig{
		LocalDomainName: "lan",
		Conf4: dhcpd.V4ServerConf{
			LeaseDuration: dhcpd.DefaultDHCPLeaseTTL,
			ICMPTimeout:   dhcpd.DefaultDHCPTimeoutICMP,
		},
		Conf6: dhcpd.V6ServerConf{
			LeaseDuration: dhcpd.DefaultDHCPLeaseTTL,
		},
	},
	Clients: &clientsConfig{
		Sources: &clientSourcesConfig{
			WHOIS:     true,
			ARP:       true,
			RDNS:      true,
			DHCP:      true,
			HostsFile: true,
		},
	},
	Log: logSettings{
		Enabled:    true,
		File:       "",
		MaxBackups: 0,
		MaxSize:    100,
		MaxAge:     3,
		Compress:   false,
		LocalTime:  false,
		Verbose:    false,
	},
	OSConfig:      &osConfig{},
	SchemaVersion: configmigrate.LastSchemaVersion,
	Theme:         ThemeAuto,
}

// configFilePath returns the absolute path to the symlink-evaluated path to the
// current config file.
func configFilePath() (confPath string) {
	confPath, err := filepath.EvalSymlinks(globalContext.confFilePath)
	if err != nil {
		confPath = globalContext.confFilePath
		logFunc := log.Error
		if errors.Is(err, os.ErrNotExist) {
			logFunc = log.Debug
		}

		logFunc("evaluating config path: %s; using %q", err, confPath)
	}

	if !filepath.IsAbs(confPath) {
		confPath = filepath.Join(globalContext.workDir, confPath)
	}

	return confPath
}

// validateBindHosts returns error if any of binding hosts from configuration is
// not a valid IP address.
func validateBindHosts(conf *configuration) (err error) {
	if !conf.HTTPConfig.Address.IsValid() {
		return errors.Error("http.address is not a valid ip address")
	}

	for i, addr := range conf.DNS.BindHosts {
		if !addr.IsValid() {
			return fmt.Errorf("dns.bind_hosts at index %d is not a valid ip address", i)
		}
	}

	return nil
}

// parseConfig loads configuration from the YAML file, upgrading it if
// necessary.
func parseConfig() (err error) {
	// Do the upgrade if necessary.
	config.fileData, err = readConfigFile()
	if err != nil {
		return err
	}

	migrator := configmigrate.New(&configmigrate.Config{
		WorkingDir: globalContext.workDir,
		DataDir:    globalContext.getDataDir(),
	})

	var upgraded bool
	config.fileData, upgraded, err = migrator.Migrate(
		config.fileData,
		configmigrate.LastSchemaVersion,
	)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	} else if upgraded {
		confPath := configFilePath()
		log.Debug("writing config file %q after config upgrade", confPath)

		err = maybe.WriteFile(confPath, config.fileData, aghos.DefaultPermFile)
		if err != nil {
			return fmt.Errorf("writing new config: %w", err)
		}
	}

	err = yaml.Unmarshal(config.fileData, &config)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	err = validateConfig()
	if err != nil {
		return err
	}

	if config.DNS.UpstreamTimeout == 0 {
		config.DNS.UpstreamTimeout = timeutil.Duration(dnsforward.DefaultTimeout)
	}

	// Do not wrap the error because it's informative enough as is.
	return validateTLSCipherIDs(config.TLS.OverrideTLSCiphers)
}

// validateConfig returns error if the configuration is invalid.
func validateConfig() (err error) {
	err = validateBindHosts(config)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	tcpPorts := aghalg.UniqChecker[tcpPort]{}
	addPorts(tcpPorts, tcpPort(config.HTTPConfig.Address.Port()))

	udpPorts := aghalg.UniqChecker[udpPort]{}
	addPorts(udpPorts, udpPort(config.DNS.Port))

	if config.TLS.Enabled {
		addPorts(
			tcpPorts,
			tcpPort(config.TLS.PortHTTPS),
			tcpPort(config.TLS.PortDNSOverTLS),
			tcpPort(config.TLS.PortDNSCrypt),
		)

		// TODO(e.burkov):  Consider adding a udpPort with the same value when
		// we add support for HTTP/3 for web admin interface.
		addPorts(udpPorts, udpPort(config.TLS.PortDNSOverQUIC))
	}

	if err = tcpPorts.Validate(); err != nil {
		return fmt.Errorf("validating tcp ports: %w", err)
	} else if err = udpPorts.Validate(); err != nil {
		return fmt.Errorf("validating udp ports: %w", err)
	}

	if !filtering.ValidateUpdateIvl(config.Filtering.FiltersUpdateIntervalHours) {
		config.Filtering.FiltersUpdateIntervalHours = 24
	}

	return nil
}

// udpPort is the port number for UDP protocol.
type udpPort uint16

// tcpPort is the port number for TCP protocol.
type tcpPort uint16

// addPorts is a helper for ports validation that skips zero ports.
func addPorts[T tcpPort | udpPort](uc aghalg.UniqChecker[T], ports ...T) {
	for _, p := range ports {
		if p != 0 {
			uc.Add(p)
		}
	}
}

// readConfigFile reads configuration file contents.
func readConfigFile() (fileData []byte, err error) {
	if len(config.fileData) > 0 {
		return config.fileData, nil
	}

	confPath := configFilePath()
	log.Debug("reading config file %q", confPath)

	// Do not wrap the error because it's informative enough as is.
	return os.ReadFile(confPath)
}

// Saves configuration to the YAML file and also saves the user filter contents to a file
func (c *configuration) write(tlsMgr *tlsManager, auth *auth) (err error) {
	c.Lock()
	defer c.Unlock()

	if auth != nil {
		// TODO(s.chzhen):  Pass context.
		config.Users = auth.usersList(context.TODO())
	}

	if tlsMgr != nil {
		tlsConf := tlsMgr.config()
		config.TLS = *tlsConf
	}

	if globalContext.stats != nil {
		statsConf := stats.Config{}
		globalContext.stats.WriteDiskConfig(&statsConf)
		config.Stats.Interval = timeutil.Duration(statsConf.Limit)
		config.Stats.Enabled = statsConf.Enabled
		config.Stats.Ignored = statsConf.Ignored.Values()
	}

	if globalContext.queryLog != nil {
		dc := querylog.Config{}
		globalContext.queryLog.WriteDiskConfig(&dc)
		config.DNS.AnonymizeClientIP = dc.AnonymizeClientIP
		config.DNS.IgnoreNoneClientLog = dc.IgnoreNoneClientLog
		config.QueryLog.Enabled = dc.Enabled
		config.QueryLog.FileEnabled = dc.FileEnabled
		config.QueryLog.Interval = timeutil.Duration(dc.RotationIvl)
		config.QueryLog.MemSize = dc.MemSize
		config.QueryLog.Ignored = dc.Ignored.Values()
	}

	if globalContext.filters != nil {
		globalContext.filters.WriteDiskConfig(config.Filtering)
		config.Filters = config.Filtering.Filters
		config.WhitelistFilters = config.Filtering.WhitelistFilters
		config.ClientsFilters = config.Filtering.ClientsFilters
		config.UserRules = config.Filtering.UserRules
	}

	if s := globalContext.dnsServer; s != nil {
		c := dnsforward.Config{}
		s.WriteDiskConfig(&c)
		dns := &config.DNS
		dns.Config = c

		dns.PrivateRDNSResolvers = s.LocalPTRResolvers()

		addrProcConf := s.AddrProcConfig()
		config.Clients.Sources.RDNS = addrProcConf.UseRDNS
		config.Clients.Sources.WHOIS = addrProcConf.UseWHOIS
		dns.UsePrivateRDNS = addrProcConf.UsePrivateRDNS
		dns.UpstreamTimeout = timeutil.Duration(s.UpstreamTimeout())
	}

	if globalContext.dhcpServer != nil {
		globalContext.dhcpServer.WriteDiskConfig(config.DHCP)
	}

	config.Clients.Persistent = globalContext.clients.forConfig()

	confPath := configFilePath()
	log.Debug("writing config file %q", confPath)

	buf := &bytes.Buffer{}
	enc := yaml.NewEncoder(buf)
	enc.SetIndent(2)

	err = enc.Encode(config)
	if err != nil {
		return fmt.Errorf("generating config file: %w", err)
	}

	err = maybe.WriteFile(confPath, buf.Bytes(), aghos.DefaultPermFile)
	if err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	return nil
}

// validateTLSCipherIDs validates the custom TLS cipher suite IDs.
func validateTLSCipherIDs(cipherIDs []string) (err error) {
	if len(cipherIDs) == 0 {
		return nil
	}

	_, err = aghtls.ParseCiphers(cipherIDs)
	if err != nil {
		return fmt.Errorf("override_tls_ciphers: %w", err)
	}

	return nil
}

package home

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/arpdb"
	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/safesearch"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// clientsContainer is the storage of all runtime and persistent clients.
type clientsContainer struct {
	// baseLogger is used to create loggers with custom prefixes for safe search
	// filter.  It must not be nil.
	baseLogger *slog.Logger

	// logger is used for logging the operation of the client container.  It
	// must not be nil.
	logger *slog.Logger

	// storage stores information about persistent clients.
	storage *client.Storage

	// clientChecker checks if a client is blocked by the current access
	// settings.
	clientChecker BlockedClientChecker

	// lock protects all fields.
	//
	// TODO(a.garipov): Use a pointer and describe which fields are protected in
	// more detail.  Use sync.RWMutex.
	lock sync.Mutex

	// safeSearchCacheSize is the size of the safe search cache to use for
	// persistent clients.
	safeSearchCacheSize uint

	// safeSearchCacheTTL is the TTL of the safe search cache to use for
	// persistent clients.
	safeSearchCacheTTL time.Duration

	// testing is a flag that disables some features for internal tests.
	//
	// TODO(a.garipov): Awful.  Remove.
	testing bool
}

// BlockedClientChecker checks if a client is blocked by the current access
// settings.
type BlockedClientChecker interface {
	// TODO(s.chzhen):  Accept [client.FindParams].
	IsBlockedClient(ip netip.Addr, clientID string) (blocked bool, rule string, whois *whois.Info)
}

// Init initializes clients container
// dhcpServer: optional
// Note: this function must be called only once
func (clients *clientsContainer) Init(
	ctx context.Context,
	baseLogger *slog.Logger,
	objects []*clientObject,
	dhcpServer client.DHCP,
	etcHosts *aghnet.HostsContainer,
	arpDB arpdb.Interface,
	filteringConf *filtering.Config,
	sigHdlr *signalHandler,
) (err error) {
	// TODO(s.chzhen):  Refactor it.
	if clients.storage != nil {
		return errors.Error("clients container already initialized")
	}

	clients.baseLogger = baseLogger
	clients.logger = baseLogger.With(slogutil.KeyPrefix, "client_container")
	clients.safeSearchCacheSize = filteringConf.SafeSearchCacheSize
	clients.safeSearchCacheTTL = time.Minute * time.Duration(filteringConf.CacheTime)

	confClients := make([]*client.Persistent, 0, len(objects))
	for i, o := range objects {
		var p *client.Persistent
		p, err = o.toPersistent(ctx, baseLogger, clients.safeSearchCacheSize, clients.safeSearchCacheTTL)
		if err != nil {
			return fmt.Errorf("init persistent client at index %d: %w", i, err)
		}

		confClients = append(confClients, p)
	}

	// The clients.etcHosts may be nil even if config.Clients.Sources.HostsFile
	// is true, because of the deprecated option --no-etc-hosts.
	//
	// TODO(e.burkov):  The option should probably be returned, since hosts file
	// currently used not only for clients' information enrichment, but also in
	// the filtering module and upstream addresses resolution.
	var hosts client.HostsContainer
	if config.Clients.Sources.HostsFile && etcHosts != nil {
		hosts = etcHosts
	}

	clients.storage, err = client.NewStorage(ctx, &client.StorageConfig{
		BaseLogger:             baseLogger,
		Logger:                 baseLogger.With(slogutil.KeyPrefix, "client_storage"),
		Clock:                  timeutil.SystemClock{},
		InitialClients:         confClients,
		DHCP:                   dhcpServer,
		EtcHosts:               hosts,
		ARPDB:                  arpDB,
		ARPClientsUpdatePeriod: arpClientsUpdatePeriod,
		RuntimeSourceDHCP:      config.Clients.Sources.DHCP,
	})
	if err != nil {
		return fmt.Errorf("init client storage: %w", err)
	}

	sigHdlr.addClientStorage(clients.storage)

	filteringConf.ApplyClientFiltering = clients.storage.ApplyClientFiltering

	return nil
}

// webHandlersRegistered prevents a [clientsContainer] from registering its web
// handlers more than once.
//
// TODO(a.garipov): Refactor HTTP handler registration logic.
var webHandlersRegistered = false

// Start starts the clients container.
func (clients *clientsContainer) Start(ctx context.Context) (err error) {
	if clients.testing {
		return
	}

	if !webHandlersRegistered {
		webHandlersRegistered = true
		clients.registerWebHandlers()
	}

	return clients.storage.Start(ctx)
}

// clientObject is the YAML representation of a persistent client.
type clientObject struct {
	SafeSearchConf filtering.SafeSearchConfig `yaml:"safe_search"`

	// BlockedServices is the configuration of blocked services of a client.
	BlockedServices *filtering.BlockedServices `yaml:"blocked_services"`

	Name string `yaml:"name"`

	IDs              []string               `yaml:"ids"`
	Tags             []string               `yaml:"tags"`
	Filters          []filtering.FilterYAML `yaml:"filters"`
	WhitelistFilters []filtering.FilterYAML `yaml:"whitelist_filters"`
	UserRules        []string               `yaml:"user_rules"`
	Upstreams        []string               `yaml:"upstreams"`

	// UID is the unique identifier of the persistent client.
	UID client.UID `yaml:"uid"`

	// UpstreamsCacheSize is the DNS cache size (in bytes).
	//
	// TODO(d.kolyshev): Use [datasize.Bytesize].
	UpstreamsCacheSize uint32 `yaml:"upstreams_cache_size"`

	// UpstreamsCacheEnabled indicates if the DNS cache is enabled.
	UpstreamsCacheEnabled bool `yaml:"upstreams_cache_enabled"`

	UseGlobalSettings        bool `yaml:"use_global_settings"`
	FilteringEnabled         bool `yaml:"filtering_enabled"`
	ParentalEnabled          bool `yaml:"parental_enabled"`
	SafeBrowsingEnabled      bool `yaml:"safebrowsing_enabled"`
	UseGlobalBlockedServices bool `yaml:"use_global_blocked_services"`
	UseGlobalFilters         bool `yaml:"use_global_filters"`

	IgnoreQueryLog   bool `yaml:"ignore_querylog"`
	IgnoreStatistics bool `yaml:"ignore_statistics"`
}

// toPersistent returns an initialized persistent client if there are no errors.
func (o *clientObject) toPersistent(
	ctx context.Context,
	baseLogger *slog.Logger,
	safeSearchCacheSize uint,
	safeSearchCacheTTL time.Duration,
) (cli *client.Persistent, err error) {
	cli = &client.Persistent{
		Name: o.Name,

		Upstreams: o.Upstreams,

		UID: o.UID,

		UseOwnSettings:        !o.UseGlobalSettings,
		FilteringEnabled:      o.FilteringEnabled,
		ParentalEnabled:       o.ParentalEnabled,
		SafeSearchConf:        o.SafeSearchConf,
		SafeBrowsingEnabled:   o.SafeBrowsingEnabled,
		UseOwnBlockedServices: !o.UseGlobalBlockedServices,
		IgnoreQueryLog:        o.IgnoreQueryLog,
		IgnoreStatistics:      o.IgnoreStatistics,
		UpstreamsCacheEnabled: o.UpstreamsCacheEnabled,
		UpstreamsCacheSize:    o.UpstreamsCacheSize,
		UseGlobalFilters:      o.UseGlobalFilters,
		UserRules:             o.UserRules,
	}

	err = cli.SetIDs(o.IDs)
	if err != nil {
		return nil, fmt.Errorf("parsing ids: %w", err)
	}

	if (cli.UID == client.UID{}) {
		cli.UID, err = client.NewUID()
		if err != nil {
			return nil, fmt.Errorf("generating uid: %w", err)
		}
	}

	if o.SafeSearchConf.Enabled {
		logger := baseLogger.With(
			slogutil.KeyPrefix, safesearch.LogPrefix,
			safesearch.LogKeyClient, cli.Name,
		)
		var ss *safesearch.Default
		ss, err = safesearch.NewDefault(ctx, &safesearch.DefaultConfig{
			Logger:         logger,
			ServicesConfig: o.SafeSearchConf,
			ClientName:     cli.Name,
			CacheSize:      safeSearchCacheSize,
			CacheTTL:       safeSearchCacheTTL,
		})
		if err != nil {
			return nil, fmt.Errorf("init safesearch %q: %w", cli.Name, err)
		}

		cli.SafeSearch = ss
	}

	if o.BlockedServices == nil {
		o.BlockedServices = &filtering.BlockedServices{
			Schedule: schedule.EmptyWeekly(),
		}
	}

	err = o.BlockedServices.Validate()
	if err != nil {
		return nil, fmt.Errorf("init blocked services %q: %w", cli.Name, err)
	}

	cli.BlockedServices = o.BlockedServices.Clone()

	cli.Tags = slices.Clone(o.Tags)
	cli.SetFilters(o.WhitelistFilters, o.Filters)

	return cli, nil
}

// forConfig returns all currently known persistent clients as objects for the
// configuration file.
func (clients *clientsContainer) forConfig() (objs []*clientObject) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	objs = make([]*clientObject, 0, clients.storage.Size())
	clients.storage.RangeByName(func(cli *client.Persistent) (cont bool) {
		objs = append(objs, &clientObject{
			Name: cli.Name,

			BlockedServices: cli.BlockedServices.Clone(),

			IDs:              cli.Identifiers(),
			Tags:             slices.Clone(cli.Tags),
			Filters:          slices.Clone(cli.Filters),
			WhitelistFilters: slices.Clone(cli.WhitelistFilters),
			Upstreams:        slices.Clone(cli.Upstreams),
			UserRules:        slices.Clone(cli.UserRules),

			UID: cli.UID,

			UseGlobalSettings:        !cli.UseOwnSettings,
			FilteringEnabled:         cli.FilteringEnabled,
			ParentalEnabled:          cli.ParentalEnabled,
			SafeSearchConf:           cli.SafeSearchConf,
			SafeBrowsingEnabled:      cli.SafeBrowsingEnabled,
			UseGlobalBlockedServices: !cli.UseOwnBlockedServices,
			IgnoreQueryLog:           cli.IgnoreQueryLog,
			IgnoreStatistics:         cli.IgnoreStatistics,
			UpstreamsCacheEnabled:    cli.UpstreamsCacheEnabled,
			UpstreamsCacheSize:       cli.UpstreamsCacheSize,
			UseGlobalFilters:         cli.UseGlobalFilters,
		})

		return true
	})

	return objs
}

// arpClientsUpdatePeriod defines how often ARP clients are updated.
const arpClientsUpdatePeriod = 10 * time.Minute

// findMultiple is a wrapper around [clientsContainer.find] to make it a valid
// client finder for the query log.  c is never nil; if no information about the
// client is found, it returns an artificial client record by only setting the
// blocking-related fields.  err is always nil.
func (clients *clientsContainer) findMultiple(ids []string) (c *querylog.Client, err error) {
	var artClient *querylog.Client
	var art bool
	for _, id := range ids {
		ip, _ := netip.ParseAddr(id)
		c, art = clients.clientOrArtificial(ip, id)
		if art {
			artClient = c

			continue
		}

		return c, nil
	}

	return artClient, nil
}

// clientOrArtificial returns information about one client.  If art is true,
// this is an artificial client record, meaning that we currently don't have any
// records about this client besides maybe whether or not it is blocked.  c is
// never nil.
func (clients *clientsContainer) clientOrArtificial(
	ip netip.Addr,
	id string,
) (c *querylog.Client, art bool) {
	defer func() {
		c.Disallowed, c.DisallowedRule, c.WHOIS = clients.clientChecker.IsBlockedClient(ip, id)
		if c.WHOIS == nil {
			c.WHOIS = &whois.Info{}
		}
	}()

	cli, ok := clients.storage.FindLoose(ip, id)
	if ok {
		return &querylog.Client{
			Name:                  cli.Name,
			IgnoreQueryLog:        cli.IgnoreQueryLog,
			IsConfigurationClient: true,
		}, false
	}

	rc := clients.storage.ClientRuntime(ip)
	if rc != nil {
		_, host := rc.Info()

		return &querylog.Client{
			Name:  host,
			WHOIS: rc.WHOIS(),
		}, false
	}

	return &querylog.Client{
		Name: "",
	}, true
}

// shouldCountClient is a wrapper around [client.Storage.Find] to make it a
// valid client information finder for the statistics.  If no information about
// the client is found, it returns true.  Values of ids must be either a valid
// ClientID or a valid IP address.
//
// TODO(s.chzhen):  Accept [client.FindParams].
func (clients *clientsContainer) shouldCountClient(ids []string) (y bool) {
	clients.lock.Lock()
	defer clients.lock.Unlock()

	params := &client.FindParams{}
	for _, id := range ids {
		err := params.Set(id)
		if err != nil {
			// Should not happen.
			clients.logger.Warn("parsing find params", slogutil.KeyError, err)

			continue
		}

		client, ok := clients.storage.Find(params)
		if ok {
			return !client.IgnoreStatistics
		}
	}

	return true
}

// type check
var _ client.AddressUpdater = (*clientsContainer)(nil)

// UpdateAddress implements the [client.AddressUpdater] interface for
// *clientsContainer
func (clients *clientsContainer) UpdateAddress(
	ctx context.Context,
	ip netip.Addr,
	host string,
	info *whois.Info,
) {
	clients.storage.UpdateAddress(ctx, ip, host, info)
}

// close gracefully closes all the client-specific upstream configurations of
// the persistent clients.
func (clients *clientsContainer) close(ctx context.Context) (err error) {
	return clients.storage.Shutdown(ctx)
}

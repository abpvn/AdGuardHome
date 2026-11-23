package client

import (
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/aghslog"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// CommonUpstreamConfig contains common settings for custom client upstream
// configurations.
type CommonUpstreamConfig struct {
	Bootstrap               upstream.Resolver
	UpstreamTimeout         time.Duration
	BootstrapPreferIPv6     bool
	EDNSClientSubnetEnabled bool
	UseHTTP3Upstreams       bool
}

// customUpstreamConfig contains custom client upstream configuration and the
// timestamp of the latest configuration update.
type customUpstreamConfig struct {
	// proxyConf is the constructed upstream configuration for the [proxy],
	// derived from the fields below.  It is initialized on demand with
	// [newCustomUpstreamConfig].
	proxyConf *proxy.CustomUpstreamConfig

	// commonConfUpdate is the timestamp of the latest configuration update,
	// used to check against [upstreamManager.confUpdate] to determine if the
	// configuration is up to date.
	commonConfUpdate time.Time

	// upstreams is the cached list of custom upstream DNS servers used for the
	// configuration of proxyConf.
	upstreams []string

	// upstreamsCacheSize is the cached value of the cache size of the
	// upstreams, used for the configuration of proxyConf.
	upstreamsCacheSize uint32

	// upstreamsCacheEnabled is the cached value indicating whether the cache of
	// the upstreams is enabled for the configuration of proxyConf.
	upstreamsCacheEnabled bool

	// isChanged indicates whether the proxyConf needs to be updated.
	isChanged bool
}

// upstreamManager stores and updates custom client upstream configurations.
type upstreamManager struct {
	// mu protects all the fields below.  It is separate from the storage lock
	// because proxy configurations are built on demand while the storage is
	// only read for the DNS query.  The read lock allows concurrent DNS queries
	// to reuse an up-to-date configuration.
	mu sync.RWMutex

	// baseLogger is used to create loggers for client upstream configurations.
	// It should not have a prefix and must not be nil.
	baseLogger *slog.Logger

	// logger is used for logging the operation of the upstream manager.  It
	// must not be nil.
	logger *slog.Logger

	// uidToCustomConf maps persistent client UID to the custom client upstream
	// configuration.  Stored UIDs must be in sync with the [index.uidToClient].
	uidToCustomConf map[UID]*customUpstreamConfig

	// commonConf is the common upstream configuration.
	commonConf *CommonUpstreamConfig

	// clock is used to get the current time.  It must not be nil.
	clock timeutil.Clock

	// confUpdate is the timestamp of the latest common upstream configuration
	// update.
	confUpdate time.Time
}

// newUpstreamManager returns the new properly initialized upstream manager.
func newUpstreamManager(baseLogger *slog.Logger, clock timeutil.Clock) (m *upstreamManager) {
	return &upstreamManager{
		baseLogger:      baseLogger,
		logger:          baseLogger.With(slogutil.KeyPrefix, "upstream_manager"),
		uidToCustomConf: make(map[UID]*customUpstreamConfig),
		clock:           clock,
	}
}

// updateCommonUpstreamConfig updates the common upstream configuration and the
// timestamp of the latest configuration update.
func (m *upstreamManager) updateCommonUpstreamConfig(conf *CommonUpstreamConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.commonConf = conf
	m.confUpdate = m.clock.Now()
}

// updateCustomUpstreamConfig updates the stored custom client upstream
// configuration associated with the persistent client.  It also sets
// [customUpstreamConfig.isChanged] to true so [customUpstreamConfig.proxyConf]
// can be updated later in [upstreamManager.customUpstreamConfig].
func (m *upstreamManager) updateCustomUpstreamConfig(c *Persistent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cliConf, ok := m.uidToCustomConf[c.UID]
	if !ok {
		cliConf = &customUpstreamConfig{
			commonConfUpdate: m.confUpdate,
		}

		m.uidToCustomConf[c.UID] = cliConf
	}

	// TODO(s.chzhen):  Compare before cloning.
	cliConf.upstreams = slices.Clone(c.Upstreams)
	cliConf.upstreamsCacheSize = c.UpstreamsCacheSize
	cliConf.upstreamsCacheEnabled = c.UpstreamsCacheEnabled
	cliConf.isChanged = true
}

// customUpstreamConfig returns the custom client upstream configuration.
func (m *upstreamManager) customUpstreamConfig(
	uid UID,
	clientName string,
) (proxyConf *proxy.CustomUpstreamConfig) {
	m.mu.RLock()
	cliConf, ok := m.uidToCustomConf[uid]
	if !ok {
		m.mu.RUnlock()

		// TODO(s.chzhen):  Consider panic.
		m.logger.Error("no associated custom client upstream config")

		return nil
	}

	if !m.isConfigChanged(cliConf) {
		proxyConf = cliConf.proxyConf
		m.mu.RUnlock()

		return proxyConf
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Another goroutine could have rebuilt the configuration while the read
	// lock was released, so check it once more.
	cliConf, ok = m.uidToCustomConf[uid]
	if !ok {
		m.logger.Error("no associated custom client upstream config")

		return nil
	}

	if !m.isConfigChanged(cliConf) {
		return cliConf.proxyConf
	}

	if cliConf.proxyConf != nil {
		err := cliConf.proxyConf.Close()
		if err != nil {
			// TODO(s.chzhen):  Pass context.
			m.logger.Debug("closing custom upstream config", slogutil.KeyError, err)
		}
	}

	cliLogger := aghslog.NewForUpstream(m.baseLogger, aghslog.UpstreamTypeCustom).With(
		aghslog.KeyClientName,
		clientName,
	)
	proxyConf = newCustomUpstreamConfig(cliConf, m.commonConf, cliLogger)
	cliConf.proxyConf = proxyConf
	cliConf.commonConfUpdate = m.confUpdate
	cliConf.isChanged = false

	return proxyConf
}

// isConfigChanged returns true if the update is necessary for the custom client
// upstream configuration.
func (m *upstreamManager) isConfigChanged(cliConf *customUpstreamConfig) (ok bool) {
	return !m.confUpdate.Equal(cliConf.commonConfUpdate) || cliConf.isChanged
}

// clearUpstreamCache clears the upstream cache for each stored custom client
// upstream configuration.
func (m *upstreamManager) clearUpstreamCache() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, c := range m.uidToCustomConf {
		if c.proxyConf != nil {
			c.proxyConf.ClearCache()
		}
	}
}

// clearUpstreamCacheForUID clears the upstream cache for a specific client.
func (m *upstreamManager) clearUpstreamCacheForUID(uid UID) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cliConf, ok := m.uidToCustomConf[uid]
	if !ok || cliConf.proxyConf == nil {
		return
	}

	cliConf.proxyConf.ClearCache()
}

// remove deletes the custom client upstream configuration and closes
// [customUpstreamConfig.proxyConf] if necessary.
func (m *upstreamManager) remove(uid UID) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cliConf, ok := m.uidToCustomConf[uid]
	if !ok {
		// TODO(s.chzhen):  Consider panic.
		return errors.Error("no associated custom client upstream config")
	}

	delete(m.uidToCustomConf, uid)

	if cliConf.proxyConf != nil {
		return cliConf.proxyConf.Close()
	}

	return nil
}

// close shuts down each stored custom client upstream configuration.
func (m *upstreamManager) close() (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for _, c := range m.uidToCustomConf {
		if c.proxyConf == nil {
			continue
		}

		errs = append(errs, c.proxyConf.Close())
	}

	return errors.Join(errs...)
}

// newCustomUpstreamConfig returns the new properly initialized custom proxy
// upstream configuration for the client.  cliConf, conf, and cliLogger must not
// be nil.
func newCustomUpstreamConfig(
	cliConf *customUpstreamConfig,
	conf *CommonUpstreamConfig,
	cliLogger *slog.Logger,
) (proxyConf *proxy.CustomUpstreamConfig) {
	upstreams := stringutil.FilterOut(cliConf.upstreams, aghnet.IsCommentOrEmpty)
	if len(upstreams) == 0 {
		return nil
	}

	upsConf, err := proxy.ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			Logger:       cliLogger,
			Bootstrap:    conf.Bootstrap,
			Timeout:      conf.UpstreamTimeout,
			HTTPVersions: aghnet.UpstreamHTTPVersions(conf.UseHTTP3Upstreams),
			PreferIPv6:   conf.BootstrapPreferIPv6,
		},
	)
	if err != nil {
		// Should not happen because upstreams are already validated.  See
		// [Persistent.validate].
		panic(fmt.Errorf("creating custom upstream config: %w", err))
	}

	return proxy.NewCustomUpstreamConfig(
		upsConf,
		cliConf.upstreamsCacheEnabled,
		int(cliConf.upstreamsCacheSize),
		conf.EDNSClientSubnetEnabled,
	)
}

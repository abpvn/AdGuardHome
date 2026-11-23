package home

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRegressionFilter returns a filter with a single global blocking rule.
func newRegressionFilter(tb testing.TB) (f *filtering.DNSFilter) {
	tb.Helper()

	f, err := filtering.New(&filtering.Config{
		Logger:          testLogger,
		DataDir:         tb.TempDir(),
		BlockedServices: &filtering.BlockedServices{Schedule: schedule.EmptyWeekly()},
	}, []filtering.Filter{{
		ID:   1,
		Data: []byte("||global.example^"),
	}})
	require.NoError(tb, err)

	tb.Cleanup(f.Close)

	return f
}

// TestPerClientFilteringRegression pins the point at which per-client filtering
// engines are built.  It must be re-run after every optimization phase with:
//
//	go test -run TestPerClientFilteringRegression ./internal/...
func TestPerClientFilteringRegression(t *testing.T) {
	prevFilters := globalContext.filters
	t.Cleanup(func() { globalContext.filters = prevFilters })

	globalContext.filters = newRegressionFilter(t)

	clients := newClientsContainer(t)

	var (
		ownClient = &client.Persistent{
			Name:             "own-client",
			UID:              client.NewUID(),
			IPs:              []netip.Addr{netip.MustParseAddr("192.0.2.10")},
			UseGlobalFilters: false,
			Filters: []filtering.FilterYAML{{
				Enabled: true,
				Filter:  filtering.Filter{ID: 2, Data: []byte("||own.example^")},
			}},
			UserRules: []string{"||user.example^"},
		}
		globalClient = &client.Persistent{
			Name:             "global-client",
			UID:              client.NewUID(),
			IPs:              []netip.Addr{netip.MustParseAddr("192.0.2.11")},
			UseGlobalFilters: true,
		}
	)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	require.NoError(t, clients.storage.Add(ctx, ownClient))
	require.NoError(t, clients.storage.Add(ctx, globalClient))

	t.Run("warm_at_startup", func(t *testing.T) {
		// No query has been made yet, so the engine can only exist if startup
		// built it.
		clients.initAllClientDNSFtl()

		assert.True(t, globalContext.filters.HasClientFilteringEngine(ownClient.Name))
		assert.False(t, globalContext.filters.HasClientFilteringEngine(globalClient.Name))

		setts := &filtering.Settings{
			ClientName:        ownClient.Name,
			ClientIP:          ownClient.IPs[0],
			FilteringEnabled:  true,
			ProtectionEnabled: true,
		}

		res, err := globalContext.filters.CheckHostRules("own.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, filtering.FilteredBlockList, res.Reason)
		assert.True(t, res.IsClientFiltered)

		res, err = globalContext.filters.CheckHostRules("user.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, filtering.FilteredBlockList, res.Reason)

		// The global rule must still take effect for a client using global
		// filters.
		globalSetts := &filtering.Settings{
			ClientName:        globalClient.Name,
			ClientIP:          globalClient.IPs[0],
			UseGlobalFilters:  true,
			FilteringEnabled:  true,
			ProtectionEnabled: true,
		}

		res, err = globalContext.filters.CheckHostRules("global.example", dns.TypeA, globalSetts)
		require.NoError(t, err)
		assert.Equal(t, filtering.FilteredBlockList, res.Reason)
		assert.False(t, res.IsClientFiltered)
	})

	t.Run("add", func(t *testing.T) {
		c := &client.Persistent{
			Name:             "added-client",
			UID:              client.NewUID(),
			IPs:              []netip.Addr{netip.MustParseAddr("192.0.2.12")},
			UseGlobalFilters: false,
			UserRules:        []string{"||added.example^"},
		}

		require.NoError(t, clients.storage.Add(ctx, c))
		clients.ensureClientDNSFtl(c)

		assert.True(t, globalContext.filters.HasClientFilteringEngine(c.Name))
	})

	t.Run("update_global_to_own", func(t *testing.T) {
		prev := client.Persistent{
			Name:             "switching-client",
			UID:              client.NewUID(),
			UseGlobalFilters: true,
		}

		c := prev
		c.UseGlobalFilters = false
		c.UserRules = []string{"||switched.example^"}

		require.False(t, globalContext.filters.HasClientFilteringEngine(prev.Name))
		clients.updateClientDNSFtl(prev, c, false, false, false)

		assert.True(t, globalContext.filters.HasClientFilteringEngine(c.Name))

		setts := &filtering.Settings{
			ClientName:        c.Name,
			FilteringEnabled:  true,
			ProtectionEnabled: true,
		}

		res, err := globalContext.filters.CheckHostRules("switched.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, filtering.FilteredBlockList, res.Reason)
		assert.True(t, res.IsClientFiltered)
	})

	t.Run("fallback_after_filter_update", func(t *testing.T) {
		// Filter updates invalidate engines by deleting them.  The query path
		// must still rebuild such an engine from the filter settings.
		globalContext.filters.DeleteClientFtlEngine(ownClient.Name)
		require.False(t, globalContext.filters.HasClientFilteringEngine(ownClient.Name))

		setts := &filtering.Settings{
			ClientName:             ownClient.Name,
			ClientIP:               ownClient.IPs[0],
			FilteringEnabled:       true,
			ProtectionEnabled:      true,
			ClientFilters:          ownClient.Filters,
			ClientWhiteListFilters: ownClient.WhitelistFilters,
			UserRules:              ownClient.UserRules,
		}

		res, err := globalContext.filters.CheckHostRules("own.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, filtering.FilteredBlockList, res.Reason)
		assert.True(t, res.IsClientFiltered)
		assert.True(t, globalContext.filters.HasClientFilteringEngine(ownClient.Name))
	})
}

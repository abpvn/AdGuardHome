package filtering

import (
	"net/http"
	"net/netip"
	"sync"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newRegressionDNSFilter returns a filter with a single global blocking rule.
func newRegressionDNSFilter(tb testing.TB) (d *DNSFilter) {
	tb.Helper()

	d, err := New(&Config{
		Logger:      testLogger,
		DataDir:     tb.TempDir(),
		HTTPClient:  &http.Client{Timeout: testTimeout},
		MaxHTTPSize: testFilterSize,
		BlockedServices: &BlockedServices{
			Schedule: schedule.EmptyWeekly(),
		},
	}, []Filter{{
		ID:   1,
		Data: []byte("||global.example^"),
	}})
	require.NoError(tb, err)

	return d
}

// regressionClientSettings returns the minimal settings for a client query.
func regressionClientSettings(name string, useGlobal bool) (setts *Settings) {
	return &Settings{
		ClientName:        name,
		ClientIP:          netip.MustParseAddr("192.0.2.10"),
		UseGlobalFilters:  useGlobal,
		FilteringEnabled:  true,
		ProtectionEnabled: true,
	}
}

// TestPerClientFilteringRegression pins the observable behavior of per-client
// filtering.  It must be re-run after every optimization phase with:
//
//	go test -run TestPerClientFilteringRegression ./internal/...
func TestPerClientFilteringRegression(t *testing.T) {
	t.Run("global_only", func(t *testing.T) {
		d := newRegressionDNSFilter(t)

		res, err := d.CheckHostRules("global.example", dns.TypeA, regressionClientSettings("", true))
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockList, res.Reason)
		assert.False(t, res.IsClientFiltered)
	})

	t.Run("client_filters_replace_global", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		d.InitForClient("alice", nil, []FilterYAML{{
			Enabled: true,
			Filter:  Filter{ID: 2, Data: []byte("||client.example^")},
		}}, nil)

		setts := regressionClientSettings("alice", false)

		res, err := d.CheckHostRules("client.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockList, res.Reason)
		assert.True(t, res.IsClientFiltered)

		res, err = d.CheckHostRules("global.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, NotFilteredNotFound, res.Reason)
		assert.False(t, res.IsClientFiltered)
	})

	t.Run("client_allowlist", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		d.InitForClient("alice", []FilterYAML{{
			Enabled: true,
			Filter:  Filter{ID: 3, Data: []byte("@@||both.example^")},
		}}, []FilterYAML{{
			Enabled: true,
			Filter:  Filter{ID: 4, Data: []byte("||both.example^")},
		}}, nil)

		res, err := d.CheckHostRules("both.example", dns.TypeA, regressionClientSettings("alice", false))
		require.NoError(t, err)
		assert.Equal(t, NotFilteredAllowList, res.Reason)
		assert.False(t, res.IsFiltered)
		assert.True(t, res.IsClientFiltered)
	})

	t.Run("client_custom_rules", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		d.InitForClient("alice", nil, nil, []string{"||custom.example^"})

		res, err := d.CheckHostRules("custom.example", dns.TypeA, regressionClientSettings("alice", false))
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockList, res.Reason)
	})

	t.Run("client_tags_and_identifiers", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		d.InitForClient("alice", nil, nil, []string{
			"||tagged.example^$ctag=device_pc",
			"||named.example^$client=alice",
			"||untagged.example^$ctag=device_phone",
		})

		want := []struct {
			host string
			reason Reason
		}{{
			host:   "tagged.example",
			reason: FilteredBlockList,
		}, {
			host:   "named.example",
			reason: FilteredBlockList,
		}, {
			host:   "untagged.example",
			reason: NotFilteredNotFound,
		}}

		// Prebuilt sets, as supplied by Persistent.ApplyToSettings.
		setts := regressionClientSettings("alice", false)
		setts.ClientTags = []string{"device_pc", "os_linux"}
		setts.ClientTagsSet = container.NewSortedSliceSet("device_pc", "os_linux")
		setts.ClientIdentifiersSet = container.NewSortedSliceSet("alice")

		for _, tc := range want {
			res, err := d.CheckHostRules(tc.host, dns.TypeA, setts)
			require.NoError(t, err)
			assert.Equal(t, tc.reason, res.Reason, tc.host)
		}

		// The on-demand fallback must produce the same result, and must not
		// sort the stored tags in place.
		fallback := regressionClientSettings("alice", false)
		fallback.ClientTags = []string{"os_linux", "device_pc"}

		for _, tc := range want {
			res, err := d.CheckHostRules(tc.host, dns.TypeA, fallback)
			require.NoError(t, err)
			assert.Equal(t, tc.reason, res.Reason, tc.host)
		}

		assert.Equal(t, []string{"os_linux", "device_pc"}, fallback.ClientTags)
	})

	t.Run("use_global_filters", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		d.InitForClient("alice", nil, nil, []string{"||client-only.example^"})

		setts := regressionClientSettings("alice", true)

		res, err := d.CheckHostRules("global.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockList, res.Reason)
		assert.False(t, res.IsClientFiltered)

		res, err = d.CheckHostRules("client-only.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, NotFilteredNotFound, res.Reason)
	})

	t.Run("rename_engine", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		d.InitForClient("alice", nil, nil, []string{"||renamed.example^"})
		d.RenameClientEngine("alice", "bob")

		res, err := d.CheckHostRules("renamed.example", dns.TypeA, regressionClientSettings("bob", false))
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockList, res.Reason)
		assert.True(t, res.IsClientFiltered)

		res, err = d.CheckHostRules("renamed.example", dns.TypeA, regressionClientSettings("alice", false))
		require.NoError(t, err)
		assert.Equal(t, NotFilteredNotFound, res.Reason)
	})

	t.Run("delete_and_rebuild", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		d.InitForClient("alice", nil, nil, []string{"||old.example^"})
		d.DeleteClientFtlEngine("alice")
		d.InitForClient("alice", nil, nil, []string{"||new.example^"})

		setts := regressionClientSettings("alice", false)

		res, err := d.CheckHostRules("new.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockList, res.Reason)

		res, err = d.CheckHostRules("old.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, NotFilteredNotFound, res.Reason)
	})

	t.Run("blocked_services", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		rule, err := rules.NewNetworkRule("||aboutfacebook.com^", rulelist.IDBlockedService)
		require.NoError(t, err)

		setts := regressionClientSettings("alice", false)
		setts.ServicesRules = []ServiceEntry{{
			Name:  "facebook",
			Rules: []*rules.NetworkRule{rule},
		}}

		res, err := d.matchBlockedServicesRules("aboutfacebook.com", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockedService, res.Reason)
		assert.True(t, res.IsFiltered)
		assert.Equal(t, "facebook", res.ServiceName)

		setts.ProtectionEnabled = false
		res, err = d.matchBlockedServicesRules("aboutfacebook.com", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, NotFilteredNotFound, res.Reason)
	})

	t.Run("concurrent", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		d.InitForClient("alice", nil, nil, []string{"||alice.example^"})
		d.InitForClient("bob", nil, nil, []string{"||bob.example^"})

		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)

			go func(i int) {
				defer wg.Done()

				name, host := "alice", "alice.example"
				if i%2 != 0 {
					name, host = "bob", "bob.example"
				}

				res, err := d.CheckHostRules(host, dns.TypeA, regressionClientSettings(name, false))
				assert.NoError(t, err)
				assert.Equal(t, FilteredBlockList, res.Reason)
				assert.True(t, res.IsClientFiltered)
			}(i)
		}

		wg.Wait()
	})
}

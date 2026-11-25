package filtering

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
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

// hostsFromRule extracts the domain-shaped tokens of a blocked-service rule
// and expands them with common subdomains.  Wildcards are replaced with a
// concrete label so that rules matching only through a wildcard are exercised.
func hostsFromRule(text string) (hosts []string) {
	var normalized strings.Builder
	for _, r := range text {
		switch {
		case r == '.' || r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9'):
			normalized.WriteRune(r)
		default:
			normalized.WriteByte(' ')
		}
	}

	for _, tok := range strings.Fields(normalized.String()) {
		if strings.Contains(tok, ".") {
			hosts = append(hosts, tok, "www."+tok, "a.b."+tok)
		}
	}

	if strings.Contains(text, "*") {
		hosts = append(hosts, hostsFromRule(strings.ReplaceAll(text, "*", "x"))...)
	}

	return hosts
}

// requireServiceRuleNames asserts that rules hold one entry per want name, in
// the same order, and that every entry has its rules compiled.
func requireServiceRuleNames(tb testing.TB, want []string, entries []ServiceEntry) {
	tb.Helper()

	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name
		require.NotEmpty(tb, e.Rules, "service %q has no rules", e.Name)
	}

	require.Equal(tb, want, names)
}

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
			host   string
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

	t.Run("blocked_services_settings", func(t *testing.T) {
		d := newRegressionDNSFilter(t)
		InitModule(context.Background(), testLogger)

		ids := []string{"facebook", "youtube", "instagram"}
		d.conf.BlockedServices = &BlockedServices{
			IDs:      ids,
			Schedule: schedule.EmptyWeekly(),
		}

		cliAddr := netip.MustParseAddr("192.0.2.10")

		// The global path must build one entry per ID, in the configured order.
		globalSetts := regressionClientSettings("", true)
		d.ApplyGlobalFiltering(cliAddr, globalSetts)
		requireServiceRuleNames(t, ids, globalSetts.ServicesRules)

		// Applying it again must replace the entries, not append to them.
		d.ApplyGlobalFiltering(cliAddr, globalSetts)
		requireServiceRuleNames(t, ids, globalSetts.ServicesRules)

		// The client path must override the global entries with its own IDs,
		// preserving their order.
		clientIDs := []string{"linkedin", "twitter"}
		cliSetts := regressionClientSettings("alice", false)
		cliSetts.BlockedServices = &BlockedServices{
			IDs:      clientIDs,
			Schedule: schedule.EmptyWeekly(),
		}
		d.ApplyClientBlockedServices(cliSetts)
		requireServiceRuleNames(t, clientIDs, cliSetts.ServicesRules)

		// A schedule that covers the current time disables the blocked services
		// for both paths.
		d.conf.BlockedServices = &BlockedServices{
			IDs:      ids,
			Schedule: schedule.FullWeekly(),
		}

		scheduledSetts := regressionClientSettings("", true)
		d.ApplyGlobalFiltering(cliAddr, scheduledSetts)
		assert.Empty(t, scheduledSetts.ServicesRules)

		cliScheduledSetts := regressionClientSettings("alice", false)
		cliScheduledSetts.BlockedServices = &BlockedServices{
			IDs:      ids,
			Schedule: schedule.FullWeekly(),
		}
		d.ApplyClientBlockedServices(cliScheduledSetts)
		assert.Empty(t, cliScheduledSetts.ServicesRules)

		// The entries built by the global path must actually drive matching,
		// so the client-facing behavior is unchanged.
		res, err := d.matchBlockedServicesRules("aboutfacebook.com", dns.TypeA, globalSetts)
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockedService, res.Reason)
		assert.Equal(t, "facebook", res.ServiceName)
	})

	t.Run("blocked_services_matcher_equivalence", func(t *testing.T) {
		InitModule(context.Background(), testLogger)
		d := newRegressionDNSFilter(t)

		// Cover services with plain domains, subdomains and wildcards.
		ids := []string{
			"facebook", "youtube", "spotify", "epic_games", "netflix", "4chan",
		}
		cs := d.compiledBlockedServices(ids)
		require.NotNil(t, cs.matcher)
		require.Len(t, cs.entries, len(ids))

		hosts := []string{
			"example.com", "google.com", "amazon.com", "localhost", "",
		}
		for _, e := range cs.entries {
			for _, r := range e.Rules {
				hosts = append(hosts, hostsFromRule(r.Text())...)
			}
		}

		for _, host := range hosts {
			req := rules.NewRequestForHostname(host)
			var loopMatched bool
			for _, e := range cs.entries {
				for _, r := range e.Rules {
					if r.Match(req) {
						loopMatched = true

						break
					}
				}
				if loopMatched {
					break
				}
			}

			_, matcherMatched := cs.matcher.Match(host)
			require.Equalf(
				t,
				loopMatched,
				matcherMatched,
				"host %q: loop and matcher disagree",
				host,
			)
		}
	})

	t.Run("allow_engine", func(t *testing.T) {
		d := newRegressionDNSFilter(t)

		// No allow rules: the guard must skip the allow engine without
		// changing the block result.
		require.Zero(t, d.filteringEngineAllow.RulesCount())
		setts := regressionClientSettings("alice", true)
		res, err := d.CheckHostRules("global.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, FilteredBlockList, res.Reason)
		assert.False(t, res.IsClientFiltered)

		// Add an allow rule covering the blocked host.  The allow engine must
		// still win over the block engine.
		allowFilters := []Filter{{
			ID:   100,
			Data: []byte("@@||global.example^\n"),
		}}
		blockFilters := []Filter{{
			ID:   1,
			Data: []byte("||global.example^\n"),
		}}
		err = d.initFiltering(context.Background(), allowFilters, blockFilters)
		require.NoError(t, err)
		require.Positive(t, d.filteringEngineAllow.RulesCount())

		res, err = d.CheckHostRules("global.example", dns.TypeA, setts)
		require.NoError(t, err)
		assert.Equal(t, NotFilteredAllowList, res.Reason)
		assert.False(t, res.IsFiltered)
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

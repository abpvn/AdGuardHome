package filtering

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// blockedBenchIDs is a representative set of blocked-service IDs used by the
// blocked-services benchmarks.
var blockedBenchIDs = []string{
	"facebook",
	"youtube",
	"instagram",
	"twitter",
	"linkedin",
}

// newBlockedBenchFilter returns a filter with the blocked-services rules
// initialized for blockedBenchIDs.
func newBlockedBenchFilter(tb testing.TB) (d *DNSFilter) {
	tb.Helper()

	InitModule(context.Background(), testLogger)

	d = newRegressionDNSFilter(tb)
	d.conf.BlockedServices = &BlockedServices{
		IDs:      blockedBenchIDs,
		Schedule: schedule.EmptyWeekly(),
	}

	return d
}

// BenchmarkDNSFilter_ApplyBlockedServices measures the per-query cost of
// building the global blocked-services settings.
func BenchmarkDNSFilter_ApplyBlockedServices(b *testing.B) {
	d := newBlockedBenchFilter(b)

	setts := &Settings{
		ClientName:        "alice",
		ClientIP:          netip.MustParseAddr("192.0.2.10"),
		FilteringEnabled:  true,
		ProtectionEnabled: true,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ApplyBlockedServices(setts)
	}
}

// BenchmarkDNSFilter_ApplyClientBlockedServices measures the per-query cost of
// building the client-specific blocked-services settings that override the
// global ones.
func BenchmarkDNSFilter_ApplyClientBlockedServices(b *testing.B) {
	d := newBlockedBenchFilter(b)

	cliBSvc := &BlockedServices{
		IDs:      blockedBenchIDs,
		Schedule: schedule.EmptyWeekly(),
	}

	setts := &Settings{
		ClientName:        "alice",
		ClientIP:          netip.MustParseAddr("192.0.2.10"),
		BlockedServices:   cliBSvc,
		FilteringEnabled:  true,
		ProtectionEnabled: true,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.ApplyClientBlockedServices(setts)
	}
}

// BenchmarkDNSFilter_MatchBlockedServicesRules measures the per-query cost of
// checking a host that is not blocked by any service, which is the common case.
func BenchmarkDNSFilter_MatchBlockedServicesRules(b *testing.B) {
	d := newBlockedBenchFilter(b)
	setts := &Settings{ProtectionEnabled: true}
	d.ApplyBlockedServices(setts)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.matchBlockedServicesRules("example.com", dns.TypeA, setts)
	}
}

// BenchmarkDNSFilter_MatchBlockedServicesRulesNoMatcher measures the cost of
// the pre-Phase-5 path without the compiled matcher prefilter.
func BenchmarkDNSFilter_MatchBlockedServicesRulesNoMatcher(b *testing.B) {
	d := newBlockedBenchFilter(b)
	setts := &Settings{ProtectionEnabled: true}
	d.ApplyBlockedServices(setts)
	setts.ServicesMatcher = nil

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.matchBlockedServicesRules("example.com", dns.TypeA, setts)
	}
}

// BenchmarkDNSFilter_CheckHostRules measures the per-query cost of checking a
// hostname when there are no allow rules, which is the common case.
func BenchmarkDNSFilter_CheckHostRules(b *testing.B) {
	d := newRegressionDNSFilter(b)
	setts := regressionClientSettings("alice", true)
	require.Zero(b, d.filteringEngineAllow.RulesCount())

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.CheckHostRules("example.com", dns.TypeA, setts)
	}
}

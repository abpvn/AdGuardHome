package filtering

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
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

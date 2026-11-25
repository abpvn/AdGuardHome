package dnsforward

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPerClientFilteringRegression pins the per-client filtering settings and
// engine selection at the DNS query entry point.  It must be re-run after every
// optimization phase with:
//
//	go test -run TestPerClientFilteringRegression ./internal/...
func TestPerClientFilteringRegression(t *testing.T) {
	const cliID = "regression-client"

	var (
		cliFilters = []filtering.FilterYAML{{
			Enabled: true,
			Filter:  filtering.Filter{ID: 20, Data: []byte("||client-only.example^")},
		}}
		bsvc = &filtering.BlockedServices{
			IDs:      []string{"facebook"},
			Schedule: schedule.EmptyWeekly(),
		}
	)

	ctx := slogutil.ContextWithLogger(
		testutil.ContextWithTimeout(t, testTimeout),
		testLogger,
	)
	filtering.InitModule(ctx, testLogger)

	cli := &client.Persistent{
		Name:                  "regression-client",
		ClientIDs:             []client.ClientID{cliID},
		UID:                   client.NewUID(),
		Tags:                  []string{"device_pc", "os_linux"},
		Filters:               cliFilters,
		SafeSearchConf:        &filtering.SafeSearchConfig{Enabled: true},
		BlockedServices:       bsvc,
		UseOwnSettings:        true,
		FilteringEnabled:      true,
		UseOwnBlockedServices: true,
	}

	// Use the real storage so that the client gets its immutable tag and
	// identifier sets at publication time, just as in production.
	storage, err := client.NewStorage(ctx, &client.StorageConfig{
		BaseLogger: testLogger,
		Logger:     testLogger,
	})
	require.NoError(t, err)
	require.NoError(t, storage.Add(ctx, cli))

	var getClientCalls int
	cc := &clientsContainer{
		OnGetClient: func(id string, addr netip.Addr) (got *client.Persistent) {
			getClientCalls++

			assert.Equal(t, cliID, id)

			return storage.GetClient(id, addr)
		},
		OnClientCustomUpstreamConfig: func(*client.Persistent) (conf *proxy.CustomUpstreamConfig) {
			return nil
		},
		OnUpdateCommonUpstreamConfig: func(*client.CommonUpstreamConfig) {},
		OnClearUpstreamCache:         func() {},
		OnIsPersistentClient:         func(string, netip.Addr) (ok bool) { return true },
	}

	s := createTestServer(t, &filtering.Config{
		BlockingMode: filtering.BlockingModeDefault,
	}, ServerConfig{
		UDPListenAddrs:   []*net.UDPAddr{{}},
		TCPListenAddrs:   []*net.TCPAddr{{}},
		TLSConf:          &TLSConfig{},
		UpstreamMode:     proxy.UpstreamModeLoadBalance,
		EDNSClientSubnet: &EDNSClientSubnet{},
		ClientsContainer: cc,
		ServePlainDNS:    true,
	}, testTLSManager)
	s.dnsFilter.SetProtectionStatus(true, nil)

	dctx := &dnsContext{
		proxyCtx: &proxy.DNSContext{
			Req:  createTestMessage("host."),
			Addr: testClientAddrPort,
		},
		clientID: cliID,
	}

	rc := s.processInitial(ctx, testLogger, dctx)
	require.Equal(t, resultCodeSuccess, rc)
	require.Equal(t, 1, getClientCalls)
	require.Same(t, cli, dctx.cli)

	setts := dctx.setts
	require.NotNil(t, setts)
	assert.Equal(t, cli.Name, setts.ClientName)
	assert.Equal(t, testClientAddrPort.Addr(), setts.ClientIP)
	assert.Equal(t, cli.Tags, setts.ClientTags)
	assert.Equal(t, cliFilters, setts.ClientFilters)
	assert.False(t, setts.UseGlobalFilters)
	assert.Same(t, bsvc, setts.BlockedServices)
	assert.True(t, setts.FilteringEnabled)
	assert.True(t, setts.SafeSearchEnabled)
	assert.NotNil(t, setts.ClientTagsSet)
	assert.NotNil(t, setts.ClientIdentifiersSet)
	assert.NotEmpty(t, setts.ServicesRules, "client blocked services must override global ones")

	// The settings produced from the resolved client must drive the client
	// engine, not the global one.
	s.dnsFilter.InitForClient(cli.Name, cli.WhitelistFilters, cli.Filters, cli.UserRules)

	res, err := s.checkHostRules("client-only.example", dns.TypeA, setts)
	require.NoError(t, err)
	assert.Equal(t, filtering.FilteredBlockList, res.Reason)
	assert.True(t, res.IsClientFiltered)

	res, err = s.checkHostRules("nxdomain.example.org", dns.TypeA, setts)
	require.NoError(t, err)
	assert.Equal(t, filtering.NotFilteredNotFound, res.Reason)
}

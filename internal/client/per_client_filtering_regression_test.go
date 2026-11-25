package client_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/dhcpsvc"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPerClientFilteringRegression pins the filtering settings that the DNS
// query path derives from a persistent client.  It must be re-run after every
// optimization phase with:
//
//	go test -run TestPerClientFilteringRegression ./internal/...
func TestPerClientFilteringRegression(t *testing.T) {
	const (
		cliID   = "regression-client-id"
		cliName = "regression-client"
	)

	var (
		cliIP = netip.MustParseAddr("192.0.2.10")
		mac   = errors.Must(net.ParseMAC("00:11:22:33:44:55"))

		cliFilters = []filtering.FilterYAML{{
			Filter: filtering.Filter{ID: 10, Data: []byte("||client.example^")},
		}}
		cliAllowlist = []filtering.FilterYAML{{
			Filter: filtering.Filter{ID: 11, Data: []byte("@@||allowed.example^")},
		}}
		cliRules = []string{"||custom.example^"}
		bsvc     = &filtering.BlockedServices{
			IDs:      []string{"facebook"},
			Schedule: schedule.EmptyWeekly(),
		}
		safeConf = &filtering.SafeSearchConfig{Enabled: true, Google: true}
	)

	cli := &client.Persistent{
		Name:                  cliName,
		ClientIDs:             []client.ClientID{cliID},
		IPs:                   []netip.Addr{cliIP},
		Tags:                  []string{"os_linux", "device_pc"},
		Filters:               cliFilters,
		WhitelistFilters:      cliAllowlist,
		UserRules:             cliRules,
		BlockedServices:       bsvc,
		SafeSearchConf:        safeConf,
		UseOwnSettings:        true,
		FilteringEnabled:      true,
		SafeBrowsingEnabled:   true,
		ParentalEnabled:       true,
		UseOwnBlockedServices: true,
		UseGlobalFilters:      false,
	}

	s := newStorage(t, []*client.Persistent{cli})

	// The golden settings produced by the new single-resolution path must
	// match those produced before the optimizations.
	setts := &filtering.Settings{}
	s.ApplyClientFiltering(cliID, cliIP, setts)

	assert.Equal(t, cliName, setts.ClientName)
	assert.Equal(t, []string{"device_pc", "os_linux"}, setts.ClientTags)
	assert.Equal(t, cliFilters, setts.ClientFilters)
	assert.Equal(t, cliAllowlist, setts.ClientWhiteListFilters)
	assert.Equal(t, cliRules, setts.UserRules)
	assert.False(t, setts.UseGlobalFilters)
	assert.Same(t, bsvc, setts.BlockedServices)
	assert.True(t, setts.FilteringEnabled)
	assert.True(t, setts.SafeSearchEnabled)
	assert.True(t, setts.SafeBrowsingEnabled)
	assert.True(t, setts.ParentalEnabled)

	require.NotNil(t, setts.ClientTagsSet)
	assert.True(t, setts.ClientTagsSet.Has("device_pc"))
	assert.True(t, setts.ClientTagsSet.Has("os_linux"))
	require.NotNil(t, setts.ClientIdentifiersSet)
	assert.True(t, setts.ClientIdentifiersSet.Has(cliName))

	// The stored client must not be mutated by building the settings.
	assert.Equal(t, []string{"device_pc", "os_linux"}, cli.Tags)

	t.Run("by_ip", func(t *testing.T) {
		byIP := &filtering.Settings{}
		s.ApplyClientFiltering("", cliIP, byIP)

		assert.Equal(t, cliName, byIP.ClientName)
		assert.Equal(t, setts.ClientTags, byIP.ClientTags)
		assert.Equal(t, setts.ClientFilters, byIP.ClientFilters)
		assert.Equal(t, setts.ClientIdentifiersSet, byIP.ClientIdentifiersSet)
	})

	t.Run("by_mac", func(t *testing.T) {
		dhcp := &testDHCP{
			OnLeases: func() (_ []*dhcpsvc.Lease) { return nil },
			OnHostBy: func(netip.Addr) (host string) { return "" },
			OnMACBy: func(ip netip.Addr) (got net.HardwareAddr) {
				if ip == cliIP {
					return mac
				}

				return nil
			},
		}

		ctx := testutil.ContextWithTimeout(t, testTimeout)
		ss, err := client.NewStorage(ctx, &client.StorageConfig{
			BaseLogger: testLogger,
			Logger:     testLogger,
			DHCP:       dhcp,
		})
		require.NoError(t, err)

		require.NoError(t, ss.Add(ctx, &client.Persistent{
			Name: "mac-client",
			MACs: []net.HardwareAddr{mac},
			UID:  client.NewUID(),
		}))

		macSetts := &filtering.Settings{}
		ss.ApplyClientFiltering("", cliIP, macSetts)

		assert.Equal(t, "mac-client", macSetts.ClientName)
		assert.True(t, macSetts.ClientIdentifiersSet.Has("mac-client"))
	})

	t.Run("global_client", func(t *testing.T) {
		global := &client.Persistent{
			Name:             "global-client",
			IPs:              []netip.Addr{netip.MustParseAddr("192.0.2.11")},
			UseGlobalFilters: true,
		}

		gs := newStorage(t, []*client.Persistent{global})
		globalSetts := &filtering.Settings{}
		gs.ApplyClientFiltering("", global.IPs[0], globalSetts)

		assert.Equal(t, global.Name, globalSetts.ClientName)
		assert.True(t, globalSetts.UseGlobalFilters)
		assert.Nil(t, globalSetts.ClientFilters)
		assert.Nil(t, globalSetts.BlockedServices)
		assert.False(t, globalSetts.FilteringEnabled)
	})
}

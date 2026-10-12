package dnsforward

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/constants"
	"github.com/AdguardTeam/AdGuardHome/internal/geoip"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeGeoIP is a mock [geoip.Interface] implementation for tests.
type fakeGeoIP struct {
	country string
}

// type check
var _ geoip.Interface = (*fakeGeoIP)(nil)

// Country implements the [geoip.Interface] interface for *fakeGeoIP.
func (g *fakeGeoIP) Country(_ netip.Addr) (country string, err error) {
	return g.country, nil
}

// Update implements the [geoip.Interface] interface for *fakeGeoIP.
func (g *fakeGeoIP) Update(_ netip.Addr, _ string) (err error) {
	return nil
}

// Close implements the [geoip.Interface] interface for *fakeGeoIP.
func (g *fakeGeoIP) Close() (err error) {
	return nil
}

func TestIsBlockedClientID(t *testing.T) {
	clientID := "client-1"
	clients := []string{clientID}

	a, err := newAccessCtx(nil, clients, nil, nil, nil, nil)
	require.NoError(t, err)

	assert.False(t, a.isBlockedClientID(clientID))

	a, err = newAccessCtx(nil, nil, clients, nil, nil, nil)
	require.NoError(t, err)

	assert.True(t, a.isBlockedClientID(clientID))
}

func TestIsBlockedHost(t *testing.T) {
	a, err := newAccessCtx(nil, nil, nil, []string{
		"host1",
		"*.host.com",
		"||host3.com^",
		"||*^$dnstype=HTTPS",
		"|.^",
	}, nil, nil)
	require.NoError(t, err)

	testCases := []struct {
		want assert.BoolAssertionFunc
		name string
		host string
		qt   rules.RRType
	}{{
		want: assert.True,
		name: "plain_match",
		host: "host1",
		qt:   dns.TypeA,
	}, {
		want: assert.False,
		name: "plain_mismatch",
		host: "host2",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "subdomain_match_short",
		host: "asdf.host.com",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "subdomain_match_long",
		host: "qwer.asdf.host.com",
		qt:   dns.TypeA,
	}, {
		want: assert.False,
		name: "subdomain_mismatch_no_lead",
		host: "host.com",
		qt:   dns.TypeA,
	}, {
		want: assert.False,
		name: "subdomain_mismatch_bad_asterisk",
		host: "asdf.zhost.com",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "rule_match_simple",
		host: "host3.com",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "rule_match_complex",
		host: "asdf.host3.com",
		qt:   dns.TypeA,
	}, {
		want: assert.False,
		name: "rule_mismatch",
		host: ".host3.com",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "by_qtype",
		host: "site-with-https-record.example",
		qt:   dns.TypeHTTPS,
	}, {
		want: assert.False,
		name: "by_qtype_other",
		host: "site-with-https-record.example",
		qt:   dns.TypeA,
	}, {
		want: assert.True,
		name: "ns_root",
		host: ".",
		qt:   dns.TypeNS,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.want(t, a.isBlockedHost(tc.host, tc.qt))
		})
	}
}

func TestIsBlockedIP(t *testing.T) {
	clients := []string{
		"1.2.3.4",
		"5.6.7.8/24",
	}

	allowCtx, err := newAccessCtx(nil, clients, nil, nil, nil, nil)
	require.NoError(t, err)

	blockCtx, err := newAccessCtx(nil, nil, clients, nil, nil, nil)
	require.NoError(t, err)

	testCases := []struct {
		ip          netip.Addr
		name        string
		wantRule    string
		wantBlocked bool
	}{{
		ip:          netip.MustParseAddr("1.2.3.4"),
		name:        "match_ip",
		wantRule:    "1.2.3.4",
		wantBlocked: true,
	}, {
		ip:          netip.MustParseAddr("5.6.7.100"),
		name:        "match_cidr",
		wantRule:    "5.6.7.8/24",
		wantBlocked: true,
	}, {
		ip:          netip.MustParseAddr("9.2.3.4"),
		name:        "no_match_ip",
		wantRule:    "",
		wantBlocked: false,
	}, {
		ip:          netip.MustParseAddr("9.6.7.100"),
		name:        "no_match_cidr",
		wantRule:    "",
		wantBlocked: false,
	}}

	t.Run("allow", func(t *testing.T) {
		for _, tc := range testCases {
			blocked, rule := allowCtx.isBlockedIP(tc.ip)
			assert.Equal(t, !tc.wantBlocked, blocked)
			assert.Equal(t, tc.wantRule, rule)
		}
	})

	t.Run("block", func(t *testing.T) {
		for _, tc := range testCases {
			blocked, rule := blockCtx.isBlockedIP(tc.ip)
			assert.Equal(t, tc.wantBlocked, blocked)
			assert.Equal(t, tc.wantRule, rule)
		}
	})
}

func TestIsBlockedCountry(t *testing.T) {
	blockedCountries := []string{"US", "CN"}
	allowedCountries := []string{"JP", "DE", "EU"}

	blockCtx, err := newAccessCtx(nil, nil, nil, nil, nil, blockedCountries)
	require.NoError(t, err)

	allowCtx, err := newAccessCtx(nil, nil, nil, nil, allowedCountries, nil)
	require.NoError(t, err)

	testCases := []struct {
		clientID    string
		countryCode string
		name        string
		wantBlocked bool
	}{{
		clientID:    "client-1",
		countryCode: "US",
		name:        "match_country_us",
		wantBlocked: true,
	}, {
		clientID:    "client-1",
		countryCode: "CN",
		name:        "match_country_cn",
		wantBlocked: true,
	}, {
		clientID:    "client-1",
		countryCode: "JP",
		name:        "match_country_jp_allowed",
		wantBlocked: false,
	}, {
		clientID:    "client-1",
		countryCode: "DE",
		name:        "no_match_country_de",
		wantBlocked: false,
	}, {
		clientID:    "client-1",
		countryCode: "EU # Country is really world wide",
		name:        "no_match_country_eu_longer_than_two_character",
		wantBlocked: false,
	}}

	t.Run("block", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				blocked := blockCtx.isBlockedCountry(tc.countryCode)
				assert.Equal(t, tc.wantBlocked, blocked)
			})
		}
	})

	t.Run("allow", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				blocked := allowCtx.isBlockedCountry(tc.countryCode)
				assert.Equal(t, tc.wantBlocked, blocked)
			})
		}
	})
}

func TestIsBlockedCountryPersistentClient(t *testing.T) {
	const (
		persistentClientID = "persistent_client_id"
		otherClientID      = "other_client_id"
	)

	var (
		persistentIP = netip.MustParseAddr("192.0.2.1")
		otherIP      = netip.MustParseAddr("192.0.2.2")
	)

	newServer := func(t *testing.T, blockedCountries, allowedCountries []string) (s *Server) {
		t.Helper()

		access, err := newAccessCtx(nil, nil, nil, nil, allowedCountries, blockedCountries)
		require.NoError(t, err)

		cc := &clientsContainer{
			OnCustomUpstreamConfig: func(_ string, _ netip.Addr) (conf *proxy.CustomUpstreamConfig) {
				return nil
			},
			OnUpdateCommonUpstreamConfig: func(_ *client.CommonUpstreamConfig) {},
			OnClearUpstreamCache:         func() {},
			OnIsPersistentClient: func(clientID string, cliAddr netip.Addr) (ok bool) {
				return clientID == persistentClientID || cliAddr == persistentIP
			},
		}

		s = &Server{
			baseLogger: testLogger,
			logger:     testLogger,
			addrProc:   client.EmptyAddrProc{},
			// Set the geoIP to a fixed country to make the lookup deterministic.
			geoIP:  &fakeGeoIP{country: "US"},
			access: access,
		}
		s.conf.ClientsContainer = cc

		return s
	}

	t.Run("blocklist", func(t *testing.T) {
		s := newServer(t, []string{"US"}, nil)

		blocked, _, _ := s.IsBlockedClient(persistentIP, persistentClientID)
		assert.False(t, blocked, "persistent client must bypass country block")

		blocked, rule, _ := s.IsBlockedClient(otherIP, otherClientID)
		assert.True(t, blocked, "non-persistent client must be blocked")
		assert.Equal(t, constants.CountryPrefix+"US", rule)

		blocked, _, _ = s.IsBlockedClient(otherIP, "")
		assert.True(t, blocked, "non-persistent ip must be blocked")
	})

	t.Run("allowlist", func(t *testing.T) {
		s := newServer(t, nil, []string{"JP"})

		blocked, _, _ := s.IsBlockedClient(persistentIP, persistentClientID)
		assert.False(t, blocked, "persistent client must bypass country allowlist")

		blocked, _, _ = s.IsBlockedClient(otherIP, otherClientID)
		assert.True(t, blocked, "non-persistent client must be blocked by country allowlist")
	})

	t.Run("ip_blocklist_still_applies", func(t *testing.T) {
		access, err := newAccessCtx(nil, nil, []string{persistentIP.String()}, nil, nil, []string{"US"})
		require.NoError(t, err)

		s := &Server{
			baseLogger: testLogger,
			logger:     testLogger,
			addrProc:   client.EmptyAddrProc{},
			geoIP:      &fakeGeoIP{country: "US"},
			access:     access,
		}

		blocked, _, _ := s.IsBlockedClient(persistentIP, persistentClientID)
		assert.True(t, blocked, "persistent client must still be blocked by ip blocklist")
	})
}

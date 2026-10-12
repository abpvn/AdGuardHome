package dnsforward

import (
	"net/netip"

	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/dnsproxy/proxy"
)

// ClientsContainer provides information about preconfigured DNS clients.
type ClientsContainer interface {
	// CustomUpstreamConfig returns the custom client upstream configuration, if
	// any.  It prioritizes ClientID over client IP address to identify the
	// client.
	CustomUpstreamConfig(clientID string, cliAddr netip.Addr) (conf *proxy.CustomUpstreamConfig)

	// UpdateCommonUpstreamConfig updates the common upstream configuration.
	UpdateCommonUpstreamConfig(conf *client.CommonUpstreamConfig)

	// ClearUpstreamCache clears the upstream cache for each stored custom
	// client upstream configuration.
	ClearUpstreamCache()

	// IsPersistentClient reports whether the client identified by clientID or
	// cliAddr is a configured persistent client.
	IsPersistentClient(clientID string, cliAddr netip.Addr) (ok bool)
}

// EmptyClientsContainer is an [ClientsContainer] implementation that does nothing.
type EmptyClientsContainer struct{}

// type check
var _ ClientsContainer = EmptyClientsContainer{}

// CustomUpstreamConfig implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) CustomUpstreamConfig(
	clientID string,
	cliAddr netip.Addr,
) (conf *proxy.CustomUpstreamConfig) {
	return nil
}

// UpdateCommonUpstreamConfig implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) UpdateCommonUpstreamConfig(conf *client.CommonUpstreamConfig) {}

// ClearUpstreamCache implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) ClearUpstreamCache() {}

// IsPersistentClient implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) IsPersistentClient(_ string, _ netip.Addr) (ok bool) {
	return false
}

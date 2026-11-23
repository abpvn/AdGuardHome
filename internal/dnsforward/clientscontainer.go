package dnsforward

import (
	"net/netip"

	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/dnsproxy/proxy"
)

// ClientsContainer provides information about preconfigured DNS clients.
type ClientsContainer interface {
	// GetClient returns the persistent client identified by clientID or cliAddr,
	// prioritizing clientID.  The returned client must be treated as read-only.
	// It is nil when there is no match.
	GetClient(clientID string, cliAddr netip.Addr) (cli *client.Persistent)

	// ClientCustomUpstreamConfig returns the custom upstream configuration of
	// cli, if any.  cli may be nil.
	ClientCustomUpstreamConfig(cli *client.Persistent) (conf *proxy.CustomUpstreamConfig)

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

// GetClient implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) GetClient(_ string, _ netip.Addr) (cli *client.Persistent) {
	return nil
}

// ClientCustomUpstreamConfig implements the [ClientsContainer] interface for
// EmptyClientsContainer.
func (EmptyClientsContainer) ClientCustomUpstreamConfig(_ *client.Persistent) (conf *proxy.CustomUpstreamConfig) {
	return nil
}

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

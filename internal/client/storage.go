package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/arpdb"
	"github.com/AdguardTeam/AdGuardHome/internal/dhcpsvc"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/timeutil"
)

// allowedTags is the list of available client tags.
var allowedTags = []string{
	"device_audio",
	"device_camera",
	"device_gameconsole",
	"device_laptop",
	"device_nas", // Network-attached Storage
	"device_other",
	"device_pc",
	"device_phone",
	"device_printer",
	"device_securityalarm",
	"device_tablet",
	"device_tv",

	"os_android",
	"os_ios",
	"os_linux",
	"os_macos",
	"os_other",
	"os_windows",

	"user_admin",
	"user_child",
	"user_regular",
}

// DHCP is an interface for accessing DHCP lease data the [Storage] needs.
type DHCP interface {
	// Leases returns all the DHCP leases.
	Leases() (leases []*dhcpsvc.Lease)

	// HostByIP returns the hostname of the DHCP client with the given IP
	// address.  host will be empty if there is no such client, due to an
	// assumption that a DHCP client must always have a hostname.
	HostByIP(ip netip.Addr) (host string)

	// MACByIP returns the MAC address for the given IP address leased.  It
	// returns nil if there is no such client, due to an assumption that a DHCP
	// client must always have a MAC address.
	MACByIP(ip netip.Addr) (mac net.HardwareAddr)
}

// EmptyDHCP is the empty [DHCP] implementation that does nothing.
type EmptyDHCP struct{}

// type check
var _ DHCP = EmptyDHCP{}

// Leases implements the [DHCP] interface for emptyDHCP.
func (EmptyDHCP) Leases() (leases []*dhcpsvc.Lease) { return nil }

// HostByIP implements the [DHCP] interface for emptyDHCP.
func (EmptyDHCP) HostByIP(_ netip.Addr) (host string) { return "" }

// MACByIP implements the [DHCP] interface for emptyDHCP.
func (EmptyDHCP) MACByIP(_ netip.Addr) (mac net.HardwareAddr) { return nil }

// HostsContainer is an interface for receiving updates to the system hosts
// file.
type HostsContainer interface {
	Upd() (updates <-chan *hostsfile.DefaultStorage)
}

// StorageConfig is the client storage configuration structure.
type StorageConfig struct {
	// Logger is used for logging the operation of the client storage.  It must
	// not be nil.
	Logger *slog.Logger

	// Clock is used by [upstreamManager] to retrieve the current time.  It must
	// not be nil.
	Clock timeutil.Clock

	// DHCP is used to match IPs against MACs of persistent clients and update
	// [SourceDHCP] runtime client information.  It must not be nil.
	DHCP DHCP

	// EtcHosts is used to update [SourceHostsFile] runtime client information.
	EtcHosts HostsContainer

	// ARPDB is used to update [SourceARP] runtime client information.
	ARPDB arpdb.Interface

	// InitialClients is a list of persistent clients parsed from the
	// configuration file.  Each client must not be nil.
	InitialClients []*Persistent

	// ARPClientsUpdatePeriod defines how often [SourceARP] runtime client
	// information is updated.
	ARPClientsUpdatePeriod time.Duration

	// RuntimeSourceDHCP specifies whether to update [SourceDHCP] information
	// of runtime clients.
	RuntimeSourceDHCP bool
}

// Storage contains information about persistent and runtime clients.
type Storage struct {
	// logger is used for logging the operation of the client storage.  It must
	// not be nil.
	logger *slog.Logger

	// mu protects indexes of persistent and runtime clients.
	mu *sync.Mutex

	// index contains information about persistent clients.
	index *index

	// runtimeIndex contains information about runtime clients.
	runtimeIndex *runtimeIndex

	// upstreamManager stores and updates custom client upstream configurations.
	upstreamManager *upstreamManager

	// dhcp is used to update [SourceDHCP] runtime client information.
	dhcp DHCP

	// etcHosts is used to update [SourceHostsFile] runtime client information.
	etcHosts HostsContainer

	// arpDB is used to update [SourceARP] runtime client information.
	arpDB arpdb.Interface

	// done is the shutdown signaling channel.
	done chan struct{}

	// allowedTags is a sorted list of all allowed tags.  It must not be
	// modified after initialization.
	//
	// TODO(s.chzhen):  Use custom type.
	allowedTags []string

	// arpClientsUpdatePeriod defines how often [SourceARP] runtime client
	// information is updated.  It must be greater than zero.
	arpClientsUpdatePeriod time.Duration

	// runtimeSourceDHCP specifies whether to update [SourceDHCP] information
	// of runtime clients.
	runtimeSourceDHCP bool
}

// NewStorage returns initialized client storage.  conf must not be nil.
func NewStorage(ctx context.Context, conf *StorageConfig) (s *Storage, err error) {
	tags := slices.Clone(allowedTags)
	slices.Sort(tags)

	s = &Storage{
		logger:                 conf.Logger,
		mu:                     &sync.Mutex{},
		index:                  newIndex(),
		runtimeIndex:           newRuntimeIndex(),
		upstreamManager:        newUpstreamManager(conf.Logger, conf.Clock),
		dhcp:                   conf.DHCP,
		etcHosts:               conf.EtcHosts,
		arpDB:                  conf.ARPDB,
		done:                   make(chan struct{}),
		allowedTags:            tags,
		arpClientsUpdatePeriod: conf.ARPClientsUpdatePeriod,
		runtimeSourceDHCP:      conf.RuntimeSourceDHCP,
	}

	for i, p := range conf.InitialClients {
		err = s.Add(ctx, p)
		if err != nil {
			return nil, fmt.Errorf("adding client %q at index %d: %w", p.Name, i, err)
		}
	}

	s.ReloadARP(ctx)

	return s, nil
}

// Start starts the goroutines for updating the runtime client information.
//
// TODO(s.chzhen):  Pass context.
func (s *Storage) Start(ctx context.Context) (err error) {
	go s.periodicARPUpdate(ctx)
	go s.handleHostsUpdates(ctx)

	return nil
}

// Shutdown gracefully stops the client storage.
//
// TODO(s.chzhen):  Pass context.
func (s *Storage) Shutdown(_ context.Context) (err error) {
	close(s.done)

	return s.upstreamManager.close()
}

// periodicARPUpdate periodically reloads runtime clients from ARP.  It is
// intended to be used as a goroutine.
func (s *Storage) periodicARPUpdate(ctx context.Context) {
	defer slogutil.RecoverAndLog(ctx, s.logger)

	t := time.NewTicker(s.arpClientsUpdatePeriod)

	for {
		select {
		case <-t.C:
			s.ReloadARP(ctx)
		case <-s.done:
			return
		}
	}
}

// ReloadARP reloads runtime clients from ARP, if configured.
func (s *Storage) ReloadARP(ctx context.Context) {
	if s.arpDB != nil {
		s.addFromSystemARP(ctx)
	}
}

// addFromSystemARP adds the IP-hostname pairings from the output of the arp -a
// command.
func (s *Storage) addFromSystemARP(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.arpDB.Refresh(); err != nil {
		s.arpDB = arpdb.Empty{}
		s.logger.ErrorContext(ctx, "refreshing arp container", slogutil.KeyError, err)

		return
	}

	ns := s.arpDB.Neighbors()
	if len(ns) == 0 {
		s.logger.DebugContext(ctx, "refreshing arp container: the update is empty")

		return
	}

	src := SourceARP
	s.runtimeIndex.clearSource(src)

	for _, n := range ns {
		s.runtimeIndex.setInfo(n.IP, src, []string{n.Name})
	}

	removed := s.runtimeIndex.removeEmpty()

	s.logger.DebugContext(
		ctx,
		"updating client aliases from arp neighborhood",
		"added", len(ns),
		"removed", removed,
	)
}

// handleHostsUpdates receives the updates from the hosts container and adds
// them to the clients storage.  It is intended to be used as a goroutine.
func (s *Storage) handleHostsUpdates(ctx context.Context) {
	if s.etcHosts == nil {
		return
	}

	defer slogutil.RecoverAndLog(ctx, s.logger)

	for {
		select {
		case upd, ok := <-s.etcHosts.Upd():
			if !ok {
				return
			}

			s.addFromHostsFile(ctx, upd)
		case <-s.done:
			return
		}
	}
}

// addFromHostsFile fills the client-hostname pairing index from the system's
// hosts files.
func (s *Storage) addFromHostsFile(ctx context.Context, hosts *hostsfile.DefaultStorage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	src := SourceHostsFile
	s.runtimeIndex.clearSource(src)

	added := 0
	hosts.RangeNames(func(addr netip.Addr, names []string) (cont bool) {
		// Only the first name of the first record is considered a canonical
		// hostname for the IP address.
		//
		// TODO(e.burkov):  Consider using all the names from all the records.
		s.runtimeIndex.setInfo(addr, src, []string{names[0]})
		added++

		return true
	})

	removed := s.runtimeIndex.removeEmpty()
	s.logger.DebugContext(
		ctx,
		"updating client aliases from system hosts file",
		"added", added,
		"removed", removed,
	)
}

// type check
var _ AddressUpdater = (*Storage)(nil)

// UpdateAddress implements the [AddressUpdater] interface for *Storage
func (s *Storage) UpdateAddress(ctx context.Context, ip netip.Addr, host string, info *whois.Info) {
	// Common fast path optimization.
	if host == "" && info == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if host != "" {
		s.runtimeIndex.setInfo(ip, SourceRDNS, []string{host})
	}

	if info != nil {
		s.setWHOISInfo(ctx, ip, info)
	}
}

// UpdateDHCP updates [SourceDHCP] runtime client information.
func (s *Storage) UpdateDHCP(ctx context.Context) {
	if s.dhcp == nil || !s.runtimeSourceDHCP {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	src := SourceDHCP
	s.runtimeIndex.clearSource(src)

	added := 0
	for _, l := range s.dhcp.Leases() {
		s.runtimeIndex.setInfo(l.IP, src, []string{l.Hostname})
		added++
	}

	removed := s.runtimeIndex.removeEmpty()
	s.logger.DebugContext(
		ctx,
		"updating client aliases from dhcp",
		"added", added,
		"removed", removed,
	)
}

// setWHOISInfo sets the WHOIS information for a runtime client.
func (s *Storage) setWHOISInfo(ctx context.Context, ip netip.Addr, wi *whois.Info) {
	_, ok := s.index.findByIP(ip)
	if ok {
		s.logger.DebugContext(
			ctx,
			"persistent client is already created, ignore whois info",
			"ip", ip,
		)

		return
	}

	rc := s.runtimeIndex.client(ip)
	if rc == nil {
		rc = NewRuntime(ip)
		s.runtimeIndex.add(rc)
	}

	rc.setWHOIS(wi)

	s.logger.DebugContext(ctx, "set whois info for runtime client", "ip", ip, "whois", wi)
}

// Add stores persistent client information or returns an error.
func (s *Storage) Add(ctx context.Context, p *Persistent) (err error) {
	defer func() { err = errors.Annotate(err, "adding client: %w") }()

	err = p.validate(ctx, s.logger, s.allowedTags)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	err = s.index.clashesUID(p)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	err = s.index.clashes(p)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	s.index.add(p)
	s.upstreamManager.updateCustomUpstreamConfig(p)

	s.logger.DebugContext(
		ctx,
		"client added",
		"name", p.Name,
		"ids", p.IDs(),
		"clients_count", s.index.size(),
	)

	return nil
}

// FindByName finds persistent client by name.  And returns its shallow copy.
func (s *Storage) FindByName(name string) (p *Persistent, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok = s.index.findByName(name)
	if ok {
		return p.ShallowClone(), ok
	}

	return nil, false
}

// Find finds persistent client by string representation of the ClientID, IP
// address, or MAC.  And returns its shallow copy.
//
// TODO(s.chzhen):  Accept ClientIDData structure instead, which will contain
// the parsed IP address, if any.
func (s *Storage) Find(id string) (p *Persistent, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok = s.index.find(id)
	if ok {
		return p.ShallowClone(), ok
	}

	ip, err := netip.ParseAddr(id)
	if err != nil {
		return nil, false
	}

	foundMAC := s.dhcp.MACByIP(ip)
	if foundMAC != nil {
		return s.FindByMAC(foundMAC)
	}

	return nil, false
}

// FindLoose is like [Storage.Find] but it also tries to find a persistent
// client by IP address without zone.  It strips the IPv6 zone index from the
// stored IP addresses before comparing, because querylog entries don't have it.
// See TODO on [querylog.logEntry.IP].
//
// Note that multiple clients can have the same IP address with different zones.
// Therefore, the result of this method is indeterminate.
func (s *Storage) FindLoose(ip netip.Addr, id string) (p *Persistent, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok = s.index.find(id)
	if ok {
		return p.ShallowClone(), ok
	}

	foundMAC := s.dhcp.MACByIP(ip)
	if foundMAC != nil {
		return s.FindByMAC(foundMAC)
	}

	p = s.index.findByIPWithoutZone(ip)
	if p != nil {
		return p.ShallowClone(), true
	}

	return nil, false
}

// FindByMAC finds persistent client by MAC and returns its shallow copy.  s.mu
// is expected to be locked.
func (s *Storage) FindByMAC(mac net.HardwareAddr) (p *Persistent, ok bool) {
	p, ok = s.index.findByMAC(mac)
	if ok {
		return p.ShallowClone(), ok
	}

	return nil, false
}

// RemoveByName removes persistent client information.  ok is false if no such
// client exists by that name.
func (s *Storage) RemoveByName(ctx context.Context, name string) (ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.index.findByName(name)
	if !ok {
		return false
	}

	s.index.remove(p)

	err := s.upstreamManager.remove(p.UID)
	if err != nil {
		s.logger.DebugContext(ctx, "closing client upstreams", "name", name, slogutil.KeyError, err)
	}

	return true
}

// Update finds the stored persistent client by its name and updates its
// information from p.
func (s *Storage) Update(ctx context.Context, name string, p *Persistent) (err error) {
	defer func() { err = errors.Annotate(err, "updating client: %w") }()

	err = p.validate(ctx, s.logger, s.allowedTags)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, ok := s.index.findByName(name)
	if !ok {
		return fmt.Errorf("client %q is not found", name)
	}

	// Client p has a newly generated UID, so replace it with the stored one.
	//
	// TODO(s.chzhen):  Remove when frontend starts handling UIDs.
	p.UID = stored.UID

	err = s.index.clashes(p)
	if err != nil {
		// Don't wrap the error since there is already an annotation deferred.
		return err
	}

	s.index.remove(stored)
	s.index.add(p)

	s.upstreamManager.updateCustomUpstreamConfig(p)

	return nil
}

// RangeByName calls f for each persistent client sorted by name, unless cont is
// false.
func (s *Storage) RangeByName(f func(c *Persistent) (cont bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.index.rangeByName(f)
}

// Size returns the number of persistent clients.
func (s *Storage) Size() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.index.size()
}

// ClientRuntime returns a copy of the saved runtime client by ip.  If no such
// client exists, returns nil.
func (s *Storage) ClientRuntime(ip netip.Addr) (rc *Runtime) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rc = s.runtimeIndex.client(ip)
	if !s.runtimeSourceDHCP {
		return rc.clone()
	}

	// SourceHostsFile > SourceDHCP, so return immediately if the client is from
	// the hosts file.
	if rc != nil && rc.hostsFile != nil {
		return rc.clone()
	}

	// Otherwise, check the DHCP server and add the client information if there
	// is any.
	host := s.dhcp.HostByIP(ip)
	if host == "" {
		return rc.clone()
	}

	rc = s.runtimeIndex.setInfo(ip, SourceDHCP, []string{host})

	return rc.clone()
}

// RangeRuntime calls f for each runtime client in an undefined order.
func (s *Storage) RangeRuntime(f func(rc *Runtime) (cont bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.runtimeIndex.rangeClients(f)
}

// AllowedTags returns the list of available client tags.  tags must not be
// modified.
func (s *Storage) AllowedTags() (tags []string) {
	return s.allowedTags
}

// CustomUpstreamConfig implements the [dnsforward.ClientsContainer] interface
// for *Storage
func (s *Storage) CustomUpstreamConfig(
	id string,
	addr netip.Addr,
) (prxConf *proxy.CustomUpstreamConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.index.findByClientID(id)
	if !ok {
		c, ok = s.index.findByIP(addr)
	}

	if !ok {
		return nil
	}

	return s.upstreamManager.customUpstreamConfig(c.UID)
}

// UpdateCommonUpstreamConfig implements the [dnsforward.ClientsContainer]
// interface for *Storage
func (s *Storage) UpdateCommonUpstreamConfig(conf *CommonUpstreamConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upstreamManager.updateCommonUpstreamConfig(conf)
}

// ClearUpstreamCache implements the [dnsforward.ClientsContainer] interface for
// *Storage
func (s *Storage) ClearUpstreamCache() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upstreamManager.clearUpstreamCache()
}

// ApplyClientFiltering retrieves persistent client information using the
// ClientID or client IP address, and applies it to the filtering settings.
// setts must not be nil.
func (s *Storage) ApplyClientFiltering(id string, addr netip.Addr, setts *filtering.Settings) {
	c, ok := s.index.findByClientID(id)
	if !ok {
		c, ok = s.index.findByIP(addr)
	}

	if !ok {
		foundMAC := s.dhcp.MACByIP(addr)
		if foundMAC != nil {
			c, ok = s.FindByMAC(foundMAC)
		}
	}

	if !ok {
		s.logger.Debug("no client filtering settings found", "clientid", id, "addr", addr)

		return
	}

	s.logger.Debug("applying custom client filtering settings", "client_name", c.Name)

	if c.UseOwnBlockedServices {
		setts.BlockedServices = c.BlockedServices.Clone()
	}

	setts.ClientName = c.Name
	setts.ClientTags = slices.Clone(c.Tags)
	setts.UseGlobalFilters = c.UseGlobalFilters
	if !c.UseGlobalFilters {
		setts.ClientFilters = c.Filters
		setts.ClientWhiteListFilters = c.WhitelistFilters
		setts.UserRules = c.UserRules
	}
	if !c.UseOwnSettings {
		return
	}

	setts.FilteringEnabled = c.FilteringEnabled
	setts.SafeSearchEnabled = c.SafeSearchConf.Enabled
	setts.ClientSafeSearch = c.SafeSearch
	setts.SafeBrowsingEnabled = c.SafeBrowsingEnabled
	setts.ParentalEnabled = c.ParentalEnabled
}

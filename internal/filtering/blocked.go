package filtering

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// serviceRules maps a service ID to its filtering rules.
var serviceRules map[string][]*rules.NetworkRule

// compiledServices is the compiled representation of a set of blocked
// services.  Instances are cached and shared between queries, so they must be
// treated as immutable.
type compiledServices struct {
	// entries is the rule entries in the configured service-ID order.
	entries []ServiceEntry

	// matcher is built from the same rules as entries.  It is used as a fast
	// negative prefilter in matchBlockedServicesRules.  It is nil when entries
	// is empty.
	matcher *urlfilter.DNSEngine
}

// compiledServicesCache caches compiled blocked-service sets keyed by their
// ordered service-ID list.  The key is the NUL-joined IDs; service IDs never
// contain NUL.
var compiledServicesCache = struct {
	mu    sync.RWMutex
	items map[string]*compiledServices
}{
	items: map[string]*compiledServices{},
}

// initBlockedServices initializes package-level blocked service data.  l must
// not be nil.
func initBlockedServices(ctx context.Context, l *slog.Logger) {
	svcLen := len(blockedServices)
	serviceRules = make(map[string][]*rules.NetworkRule, svcLen)

	// The rules may have changed, so previously compiled entries are stale.
	compiledServicesCache.mu.Lock()
	compiledServicesCache.items = map[string]*compiledServices{}
	compiledServicesCache.mu.Unlock()

	for i, s := range blockedServices {
		netRules := make([]*rules.NetworkRule, 0, len(s.Rules))
		for _, text := range s.Rules {
			rule, err := rules.NewNetworkRule(text, rulelist.IDBlockedService)
			if err == nil {
				netRules = append(netRules, rule)

				continue
			}

			l.ErrorContext(
				ctx,
				"parsing blocked service rule",
				"idx", i,
				"svc", s.ID,
				"rule", text,
				slogutil.KeyError, err,
			)
		}

		serviceRules[s.ID] = netRules
	}

	l.DebugContext(ctx, "initialized services", "svc_len", svcLen)
}

// BlockedServices is the configuration of blocked services.
//
// TODO(s.chzhen):  Move to a higher-level package to allow importing the client
// package into the filtering package.
// TODO(d.kolyshev):  Introduce JSON transfer struct.
type BlockedServices struct {
	// Schedule is blocked services schedule for every day of the week.
	Schedule *schedule.Weekly `json:"schedule"`

	// IDs is the names of blocked services.
	IDs []string `json:"ids"`
}

// Clone returns a deep copy of blocked services.
func (s *BlockedServices) Clone() (c *BlockedServices) {
	if s == nil {
		return nil
	}

	return &BlockedServices{
		Schedule: s.Schedule.Clone(),
		IDs:      slices.Clone(s.IDs),
	}
}

// FilterUnknownIDs filters out unknown service IDs within s and logs them at
// warning level.  It does nothing if s is nil.
func (s *BlockedServices) FilterUnknownIDs(ctx context.Context, logger *slog.Logger) {
	if s == nil {
		// [BlockedServices.Validate] handles this case.
		return
	}

	s.IDs = slices.DeleteFunc(s.IDs, func(id string) (ok bool) {
		_, isKnown := serviceRules[id]
		if !isKnown {
			logger.WarnContext(ctx, "filtered unknown service", "id", id)
		}

		return !isKnown
	})
}

// type check
var _ validate.Interface = (*BlockedServices)(nil)

// Validate implements the [validate.Interface] interface for *BlockedServices.
func (s *BlockedServices) Validate() (err error) {
	if s == nil {
		return errors.ErrNoValue
	}

	var errs []error
	for _, id := range s.IDs {
		_, ok := serviceRules[id]
		if !ok {
			errs = append(errs, fmt.Errorf("unknown blocked-service %q", id))
		}
	}

	return errors.Join(errs...)
}

// compiledBlockedServices returns the compiled representation of ids.  The
// result is cached, since the set of blocked services changes rarely while
// DNS queries are frequent.
func (d *DNSFilter) compiledBlockedServices(ids []string) (cs *compiledServices) {
	key := strings.Join(ids, "\x00")

	compiledServicesCache.mu.RLock()
	cs, ok := compiledServicesCache.items[key]
	compiledServicesCache.mu.RUnlock()
	if ok {
		return cs
	}

	compiledServicesCache.mu.Lock()
	defer compiledServicesCache.mu.Unlock()

	// Another goroutine may have built the entry while we waited for the lock.
	if cs, ok = compiledServicesCache.items[key]; ok {
		return cs
	}

	cs = d.buildCompiledBlockedServices(ids)
	compiledServicesCache.items[key] = cs

	return cs
}

// buildCompiledBlockedServices builds the compiled representation of ids.  It
// is only called by compiledBlockedServices under the cache write lock.
func (d *DNSFilter) buildCompiledBlockedServices(ids []string) (cs *compiledServices) {
	cs = &compiledServices{
		entries: make([]ServiceEntry, 0, len(ids)),
	}

	var ruleText strings.Builder
	for _, name := range ids {
		rs, ok := serviceRules[name]
		if !ok {
			d.logger.ErrorContext(context.TODO(), "unknown service name", "name", name)

			continue
		}

		cs.entries = append(cs.entries, ServiceEntry{Name: name, Rules: rs})
		for _, r := range rs {
			ruleText.WriteString(r.Text())
			ruleText.WriteByte('\n')
		}
	}

	if len(cs.entries) == 0 {
		return cs
	}

	fl := filterlist.NewBytes(&filterlist.BytesConfig{
		RulesText: []byte(ruleText.String()),
		ID:        rulelist.IDBlockedService,
	})
	st, err := filterlist.NewRuleStorage([]filterlist.Interface{fl})
	if err != nil {
		d.logger.ErrorContext(
			context.TODO(),
			"creating blocked-services matcher",
			slogutil.KeyError, err,
		)

		return cs
	}

	// The storage is backed by an immutable byte slice and is kept alive by the
	// engine for the lifetime of the process.  Closing it would invalidate the
	// engine, and filterlist.Bytes.Close is a no-op anyway.
	cs.matcher = urlfilter.NewDNSEngine(st)

	return cs
}

// applyCompiledBlockedServices assigns the cached, prebuilt entries and matcher
// for ids to setts.
func (d *DNSFilter) applyCompiledBlockedServices(setts *Settings, ids []string) {
	cs := d.compiledBlockedServices(ids)
	setts.ServicesRules = cs.entries
	setts.ServicesMatcher = cs.matcher
}

// ApplyBlockedServices - set blocked services settings for this DNS request
func (d *DNSFilter) ApplyBlockedServices(setts *Settings) {
	d.confMu.RLock()
	defer d.confMu.RUnlock()

	bsvc := d.conf.BlockedServices

	// TODO(s.chzhen):  Use startTime from [dnsforward.dnsContext].
	if bsvc.Schedule.Contains(time.Now()) {
		setts.ServicesRules = []ServiceEntry{}
		setts.ServicesMatcher = nil

		return
	}

	d.applyCompiledBlockedServices(setts, bsvc.IDs)
}

// ApplyBlockedServicesList appends filtering rules to the settings.
func (d *DNSFilter) ApplyBlockedServicesList(setts *Settings, list []string) {
	for _, name := range list {
		rules, ok := serviceRules[name]
		if !ok {
			d.logger.ErrorContext(context.TODO(), "unknown service name", "name", name)

			continue
		}

		setts.ServicesRules = append(setts.ServicesRules, ServiceEntry{
			Name:  name,
			Rules: rules,
		})
	}
}

func (d *DNSFilter) handleBlockedServicesAll(w http.ResponseWriter, r *http.Request) {
	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, struct {
		BlockedServices []blockedService `json:"blocked_services"`
		ServiceGroups   []serviceGroup   `json:"groups"`
	}{
		BlockedServices: blockedServices,
		ServiceGroups:   serviceGroups,
	})
}

// handleBlockedServicesGet is the handler for the GET
// /control/blocked_services/get HTTP API.
func (d *DNSFilter) handleBlockedServicesGet(w http.ResponseWriter, r *http.Request) {
	var bsvc *BlockedServices
	func() {
		d.confMu.RLock()
		defer d.confMu.RUnlock()

		bsvc = d.conf.BlockedServices.Clone()
	}()

	aghhttp.WriteJSONResponseOK(r.Context(), d.logger, w, r, bsvc)
}

// handleBlockedServicesUpdate is the handler for the PUT
// /control/blocked_services/update HTTP API.
func (d *DNSFilter) handleBlockedServicesUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := d.logger

	bsvc := &BlockedServices{}
	err := json.NewDecoder(r.Body).Decode(bsvc)
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusBadRequest, "json.Decode: %s", err)

		return
	}

	err = bsvc.Validate()
	if err != nil {
		aghhttp.ErrorAndLog(ctx, l, r, w, http.StatusUnprocessableEntity, "validating: %s", err)

		return
	}

	if bsvc.Schedule == nil {
		bsvc.Schedule = schedule.EmptyWeekly()
	}

	func() {
		d.confMu.Lock()
		defer d.confMu.Unlock()

		d.conf.BlockedServices = bsvc
	}()

	l.DebugContext(ctx, "updated blocked services schedule", "len", len(bsvc.IDs))

	d.conf.ConfModifier.Apply(ctx)
}

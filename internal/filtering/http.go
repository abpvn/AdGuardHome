package filtering

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/miekg/dns"
)

// ValidateFilterURL validates the filter list URL or file name.
func (d *DNSFilter) ValidateFilterURL(urlStr string) (err error) {
	defer func() { err = errors.Annotate(err, "checking filter: %w") }()

	if filepath.IsAbs(urlStr) {
		urlStr = filepath.Clean(urlStr)
		_, err = os.Stat(urlStr)
		if err != nil {
			// Don't wrap the error since it's informative enough as is.
			return err
		}

		if !pathMatchesAny(d.safeFSPatterns, urlStr) {
			return fmt.Errorf("path %q does not match safe patterns", urlStr)
		}

		return nil
	}

	u, err := url.ParseRequestURI(urlStr)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	err = urlutil.ValidateHTTPURL(u)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return nil
}

type filterAddJSON struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Whitelist bool   `json:"whitelist"`
}

func (d *DNSFilter) handleFilteringAddURL(w http.ResponseWriter, r *http.Request) {
	fj := filterAddJSON{}
	err := json.NewDecoder(r.Body).Decode(&fj)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "Failed to parse request body json: %s", err)

		return
	}

	err = d.ValidateFilterURL(fj.URL)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	// Check for duplicates
	if d.filterExists(fj.URL) {
		err = errFilterExists
		aghhttp.Error(r, w, http.StatusBadRequest, "Filter with URL %q: %s", fj.URL, err)

		return
	}

	// Set necessary properties
	filt := FilterYAML{
		Enabled: true,
		URL:     fj.URL,
		Name:    fj.Name,
		white:   fj.Whitelist,
		Filter: Filter{
			ID: d.idGen.next(),
		},
	}

	// Download the filter contents
	ok, err := d.Update(&filt)
	if err != nil {
		aghhttp.Error(
			r,
			w,
			http.StatusBadRequest,
			"Couldn't fetch filter from URL %q: %s",
			filt.URL,
			err,
		)

		return
	}

	if !ok {
		aghhttp.Error(
			r,
			w,
			http.StatusBadRequest,
			"Filter with URL %q is invalid (maybe it points to blank page?)",
			filt.URL,
		)

		return
	}

	// URL is assumed valid so append it to filters, update config, write new
	// file and reload it to engines.
	err = d.filterAdd(filt)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "Filter with URL %q: %s", filt.URL, err)

		return
	}

	d.conf.ConfigModified()
	d.EnableFilters(true)

	_, err = fmt.Fprintf(w, "OK %d rules\n", filt.RulesCount)
	if err != nil {
		aghhttp.Error(r, w, http.StatusInternalServerError, "Couldn't write body: %s", err)
	}
}

func (d *DNSFilter) handleFilteringRemoveURL(w http.ResponseWriter, r *http.Request) {
	type request struct {
		URL       string `json:"url"`
		Whitelist bool   `json:"whitelist"`
	}

	ctx := r.Context()

	req := request{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "failed to parse request body json: %s", err)

		return
	}

	var deleted FilterYAML
	func() {
		d.conf.filtersMu.Lock()
		defer d.conf.filtersMu.Unlock()

		filters := &d.conf.Filters
		if req.Whitelist {
			filters = &d.conf.WhitelistFilters
		}

		delIdx := slices.IndexFunc(*filters, func(flt FilterYAML) bool {
			return flt.URL == req.URL
		})
		if delIdx == -1 {
			d.logger.ErrorContext(
				ctx,
				"deleting filter",
				"url", req.URL,
				slogutil.KeyError, errFilterNotExist,
			)

			return
		}

		deleted = (*filters)[delIdx]
		p := deleted.Path(d.conf.DataDir)
		err = os.Rename(p, p+".old")
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			d.logger.ErrorContext(
				ctx,
				"renaming filter file",
				"id", deleted.ID,
				"path", p,
				slogutil.KeyError, err,
			)

			return
		}

		*filters = slices.Delete(*filters, delIdx, delIdx+1)

		d.logger.InfoContext(ctx, "deleted filter", "id", deleted.ID)
	}()

	d.conf.ConfigModified()
	d.EnableFilters(true)

	// NOTE: The old files "filter.txt.old" aren't deleted.  It's not really
	// necessary, but will require the additional complicated code to run
	// after enableFilters is done.
	//
	// TODO(a.garipov): Make sure the above comment is true.

	_, err = fmt.Fprintf(w, "OK %d rules\n", deleted.RulesCount)
	if err != nil {
		aghhttp.Error(r, w, http.StatusInternalServerError, "couldn't write body: %s", err)
	}
}

type filterURLReqData struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type filterURLReq struct {
	Data      *filterURLReqData `json:"data"`
	URL       string            `json:"url"`
	Whitelist bool              `json:"whitelist"`
}

func (d *DNSFilter) handleFilteringSetURL(w http.ResponseWriter, r *http.Request) {
	fj := filterURLReq{}
	err := json.NewDecoder(r.Body).Decode(&fj)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "decoding request: %s", err)

		return
	}

	if fj.Data == nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", errors.Error("data is absent"))

		return
	}

	err = d.ValidateFilterURL(fj.Data.URL)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "invalid url: %s", err)

		return
	}

	filt := FilterYAML{
		Enabled: fj.Data.Enabled,
		Name:    fj.Data.Name,
		URL:     fj.Data.URL,
	}

	restart, err := d.filterSetProperties(fj.URL, filt, fj.Whitelist)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	d.conf.ConfigModified()
	if restart {
		d.EnableFilters(true)
	}
}

// filteringRulesReq is the JSON structure for settings custom filtering rules.
type filteringRulesReq struct {
	Rules []string `json:"rules"`
}

func (d *DNSFilter) handleFilteringSetRules(w http.ResponseWriter, r *http.Request) {
	if aghhttp.WriteTextPlainDeprecated(w, r) {
		return
	}

	req := &filteringRulesReq{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "reading req: %s", err)

		return
	}

	d.conf.UserRules = req.Rules
	d.conf.ConfigModified()
	d.EnableFilters(true)
	for clientName := range d.ClientsGlobalCustomRules {
		d.DeleteClientFtlEngine(clientName)
	}
}

// DeleteClientFtlEngine delete exist client filtering engine to re init in next time
func (d *DNSFilter) DeleteClientFtlEngine(clientName string) {
	d.clientEngineLock.Lock()
	defer d.clientEngineLock.Unlock()
	delete(d.ClientsRulesStorage, clientName)
	delete(d.ClientsFilteringEngine, clientName)
	delete(d.ClientsRulesStorageAllow, clientName)
	delete(d.ClientsFilteringEngineAllow, clientName)
}

func (d *DNSFilter) handleFilteringRefresh(w http.ResponseWriter, r *http.Request) {
	type Req struct {
		White  bool    `json:"whitelist"`
		Client *string `json:"client"`
	}
	var err error

	req := Req{}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	var ok bool
	resp := struct {
		Updated int `json:"updated"`
	}{}
	resp.Updated, _, ok = d.tryRefreshFilters(req.Client == nil && !req.White, req.Client == nil && req.White, true, req.Client)
	if !ok {
		aghhttp.Error(
			r,
			w,
			http.StatusInternalServerError,
			"filters update procedure is already running",
		)

		return
	}

	aghhttp.WriteJSONResponseOK(w, r, resp)
}

type FilterJSON struct {
	URL         string               `json:"url"`
	Name        string               `json:"name"`
	LastUpdated string               `json:"last_updated,omitempty"`
	ID          rulelist.URLFilterID `json:"id"`
	RulesCount  uint32               `json:"rules_count"`
	Enabled     bool                 `json:"enabled"`
}

type ClientFilterJSON struct {
	Names map[string]string `json:"names"`

	FilterJSON `json:",inline"`
}

type filteringConfig struct {
	Filters          []FilterJSON       `json:"filters"`
	WhitelistFilters []FilterJSON       `json:"whitelist_filters"`
	ClientsFilters   []ClientFilterJSON `json:"clients_filters"`
	UserRules        []string           `json:"user_rules"`
	Interval         uint32             `json:"interval"` // in hours
	Enabled          bool               `json:"enabled"`
}

func FilterToJSON(f FilterYAML) FilterJSON {
	fj := FilterJSON{
		ID:         f.ID,
		Enabled:    f.Enabled,
		URL:        f.URL,
		Name:       f.Name,
		RulesCount: uint32(f.RulesCount),
	}

	if !f.LastUpdated.IsZero() {
		fj.LastUpdated = f.LastUpdated.Format(time.RFC3339)
	}

	return fj
}

func ClientFilterToJSON(f ClientFilterYAML) ClientFilterJSON {
	cfj := ClientFilterJSON{
		FilterJSON: FilterToJSON(*f.FilterYAML),
		Names:      f.Names,
	}
	if !f.LastUpdated.IsZero() {
		cfj.LastUpdated = f.LastUpdated.Format(time.RFC3339)
	}

	return cfj
}

func (fj *FilterJSON) ToFilterYAML() FilterYAML {
	fy := FilterYAML{
		Enabled:    fj.Enabled,
		URL:        fj.URL,
		Name:       fj.Name,
		RulesCount: int(fj.RulesCount),
		Filter:     Filter{ID: fj.ID},
	}
	if fj.LastUpdated != "" {
		fy.LastUpdated, _ = time.Parse(time.RFC3339, fj.LastUpdated)
	}
	return fy
}

// Get filtering configuration
func (d *DNSFilter) handleFilteringStatus(w http.ResponseWriter, r *http.Request) {
	resp := filteringConfig{}
	d.conf.filtersMu.RLock()
	resp.Enabled = d.conf.FilteringEnabled
	resp.Interval = d.conf.FiltersUpdateIntervalHours
	for _, f := range d.conf.Filters {
		fj := FilterToJSON(f)
		resp.Filters = append(resp.Filters, fj)
	}
	for _, f := range d.conf.WhitelistFilters {
		fj := FilterToJSON(f)
		resp.WhitelistFilters = append(resp.WhitelistFilters, fj)
	}
	for _, f := range d.conf.ClientsFilters {
		fj := ClientFilterToJSON(f)
		resp.ClientsFilters = append(resp.ClientsFilters, fj)
	}
	resp.UserRules = d.conf.UserRules
	d.conf.filtersMu.RUnlock()

	aghhttp.WriteJSONResponseOK(w, r, resp)
}

// Set filtering configuration
func (d *DNSFilter) handleFilteringConfig(w http.ResponseWriter, r *http.Request) {
	req := filteringConfig{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "json decode: %s", err)

		return
	}

	if !ValidateUpdateIvl(req.Interval) {
		aghhttp.Error(r, w, http.StatusBadRequest, "Unsupported interval")

		return
	}

	func() {
		d.conf.filtersMu.Lock()
		defer d.conf.filtersMu.Unlock()

		d.conf.FilteringEnabled = req.Enabled
		d.conf.FiltersUpdateIntervalHours = req.Interval
	}()

	d.conf.ConfigModified()
	d.EnableFilters(true)
}

type checkHostRespRule struct {
	Text         string               `json:"text"`
	FilterListID rulelist.URLFilterID `json:"filter_list_id"`
}

type checkHostResp struct {
	Reason string `json:"reason"`

	// Rule is the text of the matched rule.
	//
	// Deprecated: Use Rules[*].Text.
	Rule string `json:"rule"`

	Rules []*checkHostRespRule `json:"rules"`

	// for FilteredBlockedService:
	SvcName string `json:"service_name"`

	// for Rewrite:
	CanonName string       `json:"cname"`    // CNAME value
	IPList    []netip.Addr `json:"ip_addrs"` // list of IP addresses

	// FilterID is the ID of the rule's filter list.
	//
	// Deprecated: Use Rules[*].FilterListID.
	FilterID rulelist.URLFilterID `json:"filter_id"`
}

// handleCheckHost is the handler for the GET /control/filtering/check_host HTTP
// API.
func (d *DNSFilter) handleCheckHost(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	host := query.Get("name")
	if host == "" {
		aghhttp.Error(
			r,
			w,
			http.StatusBadRequest,
			`query parameter "name" is required`,
		)

		return
	}

	cli := query.Get("client")
	qTypeStr := query.Get("qtype")
	qType, err := stringToDNSType(qTypeStr)
	if err != nil {
		aghhttp.Error(
			r,
			w,
			http.StatusUnprocessableEntity,
			"bad qtype query parameter: %q",
			qTypeStr,
		)

		return
	}

	setts := d.Settings()
	setts.FilteringEnabled = true
	setts.ProtectionEnabled = true

	addr, err := netip.ParseAddr(cli)
	if err == nil {
		d.ApplyAdditionalFiltering(addr, "", setts)
	} else if cli != "" {
		// TODO(s.chzhen):  Set [Settings.ClientName] once urlfilter supports
		// multiple client names.  This will handle the case when a rule exists
		// but the persistent client does not.
		d.ApplyAdditionalFiltering(netip.Addr{}, cli, setts)
	}

	result, err := d.CheckHost(host, qType, setts)
	if err != nil {
		aghhttp.Error(
			r,
			w,
			http.StatusInternalServerError,
			"couldn't apply filtering: %s: %s",
			host,
			err,
		)

		return
	}

	rulesLen := len(result.Rules)
	resp := checkHostResp{
		Reason:    result.Reason.String(),
		SvcName:   result.ServiceName,
		CanonName: result.CanonName,
		IPList:    result.IPList,
		Rules:     make([]*checkHostRespRule, len(result.Rules)),
	}

	if rulesLen > 0 {
		resp.FilterID = result.Rules[0].FilterListID
		resp.Rule = result.Rules[0].Text
	}

	for i, r := range result.Rules {
		resp.Rules[i] = &checkHostRespRule{
			FilterListID: r.FilterListID,
			Text:         r.Text,
		}
	}

	aghhttp.WriteJSONResponseOK(w, r, resp)
}

// stringToDNSType is a helper function that converts a string to DNS type.  If
// the string is empty, it returns the default value [dns.TypeA].
func stringToDNSType(str string) (qtype uint16, err error) {
	if str == "" {
		return dns.TypeA, nil
	}

	qtype, ok := dns.StringToType[str]
	if ok {
		return qtype, nil
	}

	// typePref is a prefix for DNS types from experimental RFCs.
	const typePref = "TYPE"

	if !strings.HasPrefix(str, typePref) {
		return 0, errors.ErrBadEnumValue
	}

	val, err := strconv.ParseUint(str[len(typePref):], 10, 16)
	if err != nil {
		return 0, errors.ErrBadEnumValue
	}

	return uint16(val), nil
}

// setProtectedBool sets the value of a boolean pointer under a lock.  l must
// protect the value under ptr.
//
// TODO(e.burkov):  Make it generic?
func setProtectedBool(mu *sync.RWMutex, ptr *bool, val bool) {
	mu.Lock()
	defer mu.Unlock()

	*ptr = val
}

// protectedBool gets the value of a boolean pointer under a read lock.  l must
// protect the value under ptr.
//
// TODO(e.burkov):  Make it generic?
func protectedBool(mu *sync.RWMutex, ptr *bool) (val bool) {
	mu.RLock()
	defer mu.RUnlock()

	return *ptr
}

// handleSafeBrowsingEnable is the handler for the POST
// /control/safebrowsing/enable HTTP API.
func (d *DNSFilter) handleSafeBrowsingEnable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.SafeBrowsingEnabled, true)
	d.conf.ConfigModified()
}

// handleSafeBrowsingDisable is the handler for the POST
// /control/safebrowsing/disable HTTP API.
func (d *DNSFilter) handleSafeBrowsingDisable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.SafeBrowsingEnabled, false)
	d.conf.ConfigModified()
}

// handleSafeBrowsingStatus is the handler for the GET
// /control/safebrowsing/status HTTP API.
func (d *DNSFilter) handleSafeBrowsingStatus(w http.ResponseWriter, r *http.Request) {
	resp := &struct {
		Enabled bool `json:"enabled"`
	}{
		Enabled: protectedBool(d.confMu, &d.conf.SafeBrowsingEnabled),
	}

	aghhttp.WriteJSONResponseOK(w, r, resp)
}

// handleParentalEnable is the handler for the POST /control/parental/enable
// HTTP API.
func (d *DNSFilter) handleParentalEnable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.ParentalEnabled, true)
	d.conf.ConfigModified()
}

// handleParentalDisable is the handler for the POST /control/parental/disable
// HTTP API.
func (d *DNSFilter) handleParentalDisable(w http.ResponseWriter, r *http.Request) {
	setProtectedBool(d.confMu, &d.conf.ParentalEnabled, false)
	d.conf.ConfigModified()
}

// handleParentalStatus is the handler for the GET /control/parental/status
// HTTP API.
func (d *DNSFilter) handleParentalStatus(w http.ResponseWriter, r *http.Request) {
	resp := &struct {
		Enabled bool `json:"enabled"`
	}{
		Enabled: protectedBool(d.confMu, &d.conf.ParentalEnabled),
	}

	aghhttp.WriteJSONResponseOK(w, r, resp)
}

// RegisterFilteringHandlers - register handlers
func (d *DNSFilter) RegisterFilteringHandlers() {
	registerHTTP := d.conf.HTTPRegister
	if registerHTTP == nil {
		return
	}

	registerHTTP(http.MethodPost, "/control/safebrowsing/enable", d.handleSafeBrowsingEnable)
	registerHTTP(http.MethodPost, "/control/safebrowsing/disable", d.handleSafeBrowsingDisable)
	registerHTTP(http.MethodGet, "/control/safebrowsing/status", d.handleSafeBrowsingStatus)

	registerHTTP(http.MethodPost, "/control/parental/enable", d.handleParentalEnable)
	registerHTTP(http.MethodPost, "/control/parental/disable", d.handleParentalDisable)
	registerHTTP(http.MethodGet, "/control/parental/status", d.handleParentalStatus)

	registerHTTP(http.MethodPost, "/control/safesearch/enable", d.handleSafeSearchEnable)
	registerHTTP(http.MethodPost, "/control/safesearch/disable", d.handleSafeSearchDisable)
	registerHTTP(http.MethodGet, "/control/safesearch/status", d.handleSafeSearchStatus)
	registerHTTP(http.MethodPut, "/control/safesearch/settings", d.handleSafeSearchSettings)

	registerHTTP(http.MethodGet, "/control/rewrite/list", d.handleRewriteList)
	registerHTTP(http.MethodPost, "/control/rewrite/add", d.handleRewriteAdd)
	registerHTTP(http.MethodPut, "/control/rewrite/update", d.handleRewriteUpdate)
	registerHTTP(http.MethodPost, "/control/rewrite/delete", d.handleRewriteDelete)

	registerHTTP(http.MethodGet, "/control/blocked_services/services", d.handleBlockedServicesIDs)
	registerHTTP(http.MethodGet, "/control/blocked_services/all", d.handleBlockedServicesAll)

	// Deprecated handlers.
	registerHTTP(http.MethodGet, "/control/blocked_services/list", d.handleBlockedServicesList)
	registerHTTP(http.MethodPost, "/control/blocked_services/set", d.handleBlockedServicesSet)

	registerHTTP(http.MethodGet, "/control/blocked_services/get", d.handleBlockedServicesGet)
	registerHTTP(http.MethodPut, "/control/blocked_services/update", d.handleBlockedServicesUpdate)

	registerHTTP(http.MethodGet, "/control/filtering/status", d.handleFilteringStatus)
	registerHTTP(http.MethodPost, "/control/filtering/config", d.handleFilteringConfig)
	registerHTTP(http.MethodPost, "/control/filtering/add_url", d.handleFilteringAddURL)
	registerHTTP(http.MethodPost, "/control/filtering/remove_url", d.handleFilteringRemoveURL)
	registerHTTP(http.MethodPost, "/control/filtering/set_url", d.handleFilteringSetURL)
	registerHTTP(http.MethodPost, "/control/filtering/refresh", d.handleFilteringRefresh)
	registerHTTP(http.MethodPost, "/control/filtering/set_rules", d.handleFilteringSetRules)
	registerHTTP(http.MethodGet, "/control/filtering/check_host", d.handleCheckHost)
}

// ValidateUpdateIvl returns false if i is not a valid filters update interval.
func ValidateUpdateIvl(i uint32) bool {
	return i == 0 || i == 1 || i == 12 || i == 1*24 || i == 3*24 || i == 7*24
}

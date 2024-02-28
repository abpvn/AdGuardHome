package home

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"slices"

	"github.com/AdguardTeam/AdGuardHome/internal/aghalg"
	"github.com/AdguardTeam/AdGuardHome/internal/aghhttp"
	"github.com/AdguardTeam/AdGuardHome/internal/client"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/schedule"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
)

// clientJSON is a common structure used by several handlers to deal with
// clients.  Some of the fields are only necessary in one or two handlers and
// are thus made pointers with an omitempty tag.
//
// TODO(a.garipov): Consider using nullbool and an optional string here?  Or
// split into several structs?
type clientJSON struct {
	// Disallowed, if non-nil and false, means that the client's IP is
	// allowed.  Otherwise, the IP is blocked.
	Disallowed *bool `json:"disallowed,omitempty"`

	// DisallowedRule is the rule due to which the client is disallowed.
	// If Disallowed is true and this string is empty, the client IP is
	// disallowed by the "allowed IP list", that is it is not included in
	// the allowlist.
	DisallowedRule *string `json:"disallowed_rule,omitempty"`

	// WHOIS is the filtered WHOIS data of a client.
	WHOIS          *whois.Info                 `json:"whois_info,omitempty"`
	SafeSearchConf *filtering.SafeSearchConfig `json:"safe_search"`

	// Schedule is blocked services schedule for every day of the week.
	Schedule *schedule.Weekly `json:"blocked_services_schedule"`

	Name string `json:"name"`

	// BlockedServices is the names of blocked services.
	BlockedServices []string               `json:"blocked_services"`
	IDs             []string               `json:"ids"`
	Tags            []string               `json:"tags"`
	Filters         []filtering.FilterJSON `json:"filters"`
	WhitelistFilter []filtering.FilterJSON `json:"whitelist_filters"`
	Upstreams       []string               `json:"upstreams"`

	FilteringEnabled    bool `json:"filtering_enabled"`
	ParentalEnabled     bool `json:"parental_enabled"`
	SafeBrowsingEnabled bool `json:"safebrowsing_enabled"`
	// Deprecated: use safeSearchConf.
	SafeSearchEnabled        bool `json:"safesearch_enabled"`
	UseGlobalBlockedServices bool `json:"use_global_blocked_services"`
	UseGlobalSettings        bool `json:"use_global_settings"`
	UseGlobalFilters         bool `json:"use_global_filters"`

	IgnoreQueryLog   aghalg.NullBool `json:"ignore_querylog"`
	IgnoreStatistics aghalg.NullBool `json:"ignore_statistics"`

	UpstreamsCacheSize    uint32          `json:"upstreams_cache_size"`
	UpstreamsCacheEnabled aghalg.NullBool `json:"upstreams_cache_enabled"`
}

// runtimeClientJSON is a JSON representation of the [client.Runtime].
type runtimeClientJSON struct {
	WHOIS *whois.Info `json:"whois_info"`

	IP     netip.Addr    `json:"ip"`
	Name   string        `json:"name"`
	Source client.Source `json:"source"`
}

// clientListJSON contains lists of persistent clients, runtime clients and also
// supported tags.
type clientListJSON struct {
	Clients        []*clientJSON       `json:"clients"`
	RuntimeClients []runtimeClientJSON `json:"auto_clients"`
	Tags           []string            `json:"supported_tags"`
}

// whoisOrEmpty returns a WHOIS client information or a pointer to an empty
// struct.  Frontend expects a non-nil value.
func whoisOrEmpty(r *client.Runtime) (info *whois.Info) {
	info = r.WHOIS()
	if info != nil {
		return info
	}

	return &whois.Info{}
}

// handleGetClients is the handler for GET /control/clients HTTP API.
func (clients *clientsContainer) handleGetClients(w http.ResponseWriter, r *http.Request) {
	data := clientListJSON{}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	for _, c := range clients.list {
		cj := clientToJSON(c)
		data.Clients = append(data.Clients, cj)
	}

	for ip, rc := range clients.ipToRC {
		src, host := rc.Info()
		cj := runtimeClientJSON{
			WHOIS:  whoisOrEmpty(rc),
			Name:   host,
			Source: src,
			IP:     ip,
		}

		data.RuntimeClients = append(data.RuntimeClients, cj)
	}

	for _, l := range clients.dhcp.Leases() {
		cj := runtimeClientJSON{
			Name:   l.Hostname,
			Source: client.SourceDHCP,
			IP:     l.IP,
			WHOIS:  &whois.Info{},
		}

		data.RuntimeClients = append(data.RuntimeClients, cj)
	}

	data.Tags = clientTags

	aghhttp.WriteJSONResponseOK(w, r, data)
}

// handleGetClients is the handler for GET /control/clients HTTP API.
func (clients *clientsContainer) handleGetClient(w http.ResponseWriter, r *http.Request) {
	data := clientJSON{}
	clientName := r.URL.Query().Get("name")

	if clientName == "" {
		aghhttp.WriteJSONResponseError(w, r, fmt.Errorf("missing required parameter name"))
		return
	}

	clients.lock.Lock()
	defer clients.lock.Unlock()

	if client, ok := clients.list[clientName]; ok {
		data = *clientToJSON(client)
	} else {
		aghhttp.WriteJSONResponseError(w, r, fmt.Errorf("client %s not found", clientName))
	}

	aghhttp.WriteJSONResponseOK(w, r, data)
}

// initPrev initializes the persistent client with the default or previous
// client properties.
func initPrev(cj clientJSON, prev *client.Persistent) (c *client.Persistent, err error) {
	var (
		uid              client.UID
		ignoreQueryLog   bool
		ignoreStatistics bool
		upsCacheEnabled  bool
		upsCacheSize     uint32
	)

	if prev != nil {
		uid = prev.UID
		ignoreQueryLog = prev.IgnoreQueryLog
		ignoreStatistics = prev.IgnoreStatistics
		upsCacheEnabled = prev.UpstreamsCacheEnabled
		upsCacheSize = prev.UpstreamsCacheSize
	}

	if cj.IgnoreQueryLog != aghalg.NBNull {
		ignoreQueryLog = cj.IgnoreQueryLog == aghalg.NBTrue
	}

	if cj.IgnoreStatistics != aghalg.NBNull {
		ignoreStatistics = cj.IgnoreStatistics == aghalg.NBTrue
	}

	if cj.UpstreamsCacheEnabled != aghalg.NBNull {
		upsCacheEnabled = cj.UpstreamsCacheEnabled == aghalg.NBTrue
		upsCacheSize = cj.UpstreamsCacheSize
	}

	svcs, err := copyBlockedServices(cj.Schedule, cj.BlockedServices, prev)
	if err != nil {
		return nil, fmt.Errorf("invalid blocked services: %w", err)
	}

	if (uid == client.UID{}) {
		uid, err = client.NewUID()
		if err != nil {
			return nil, fmt.Errorf("generating uid: %w", err)
		}
	}

	return &client.Persistent{
		BlockedServices:       svcs,
		UID:                   uid,
		IgnoreQueryLog:        ignoreQueryLog,
		IgnoreStatistics:      ignoreStatistics,
		UpstreamsCacheEnabled: upsCacheEnabled,
		UpstreamsCacheSize:    upsCacheSize,
	}, nil
}

// jsonToClient converts JSON object to persistent client object if there are no
// errors.
func (clients *clientsContainer) jsonToClient(
	cj clientJSON,
	prev *client.Persistent,
) (c *client.Persistent, err error) {
	c, err = initPrev(cj, prev)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	err = c.SetIDs(cj.IDs)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	c.SafeSearchConf = copySafeSearch(cj.SafeSearchConf, cj.SafeSearchEnabled)
	c.Name = cj.Name
	c.Tags = cj.Tags
	c.Upstreams = cj.Upstreams
	c.UseOwnSettings = !cj.UseGlobalSettings
	c.FilteringEnabled = cj.FilteringEnabled
	c.ParentalEnabled = cj.ParentalEnabled
	c.SafeBrowsingEnabled = cj.SafeBrowsingEnabled
	c.UseOwnBlockedServices = !cj.UseGlobalBlockedServices
	c.UseGlobalFilters = cj.UseGlobalFilters
	for _, fj := range cj.Filters {
		c.Filters = append(c.Filters, fj.ToFilterYAML())
	}
	for _, fj := range cj.WhitelistFilter {
		c.WhitelistFilters = append(c.WhitelistFilters, fj.ToFilterYAML())
	}

	if c.SafeSearchConf.Enabled {
		err = c.SetSafeSearch(
			c.SafeSearchConf,
			clients.safeSearchCacheSize,
			clients.safeSearchCacheTTL,
		)
		if err != nil {
			return nil, fmt.Errorf("creating safesearch for client %q: %w", c.Name, err)
		}
	}

	return c, nil
}

// copySafeSearch returns safe search config created from provided parameters.
func copySafeSearch(
	jsonConf *filtering.SafeSearchConfig,
	enabled bool,
) (conf filtering.SafeSearchConfig) {
	if jsonConf != nil {
		return *jsonConf
	}

	// TODO(d.kolyshev): Remove after cleaning the deprecated
	// [clientJSON.SafeSearchEnabled] field.
	conf = filtering.SafeSearchConfig{
		Enabled: enabled,
	}

	// Set default service flags for enabled safesearch.
	if conf.Enabled {
		conf.Bing = true
		conf.DuckDuckGo = true
		conf.Google = true
		conf.Pixabay = true
		conf.Yandex = true
		conf.YouTube = true
	}

	return conf
}

// copyBlockedServices converts a json blocked services to an internal blocked
// services.
func copyBlockedServices(
	sch *schedule.Weekly,
	svcStrs []string,
	prev *client.Persistent,
) (svcs *filtering.BlockedServices, err error) {
	var weekly *schedule.Weekly
	if sch != nil {
		weekly = sch.Clone()
	} else if prev != nil && prev.BlockedServices != nil {
		weekly = prev.BlockedServices.Schedule.Clone()
	} else {
		weekly = schedule.EmptyWeekly()
	}

	svcs = &filtering.BlockedServices{
		Schedule: weekly,
		IDs:      svcStrs,
	}

	err = svcs.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating blocked services: %w", err)
	}

	return svcs, nil
}

// clientToJSON converts persistent client object to JSON object.
func clientToJSON(c *client.Persistent) (cj *clientJSON) {
	// TODO(d.kolyshev): Remove after cleaning the deprecated
	// [clientJSON.SafeSearchEnabled] field.
	cloneVal := c.SafeSearchConf
	safeSearchConf := &cloneVal
	allowfiltersJSON := []filtering.FilterJSON{}
	blockedfiltersJSON := []filtering.FilterJSON{}
	Context.filters.LoadFilters(c.WhitelistFilters)
	Context.filters.LoadFilters(c.Filters)
	for _, filter := range c.WhitelistFilters {
		allowfiltersJSON = append(allowfiltersJSON, filtering.FilterToJSON(filter))
	}
	for _, filter := range c.Filters {
		blockedfiltersJSON = append(blockedfiltersJSON, filtering.FilterToJSON(filter))
	}

	return &clientJSON{
		Name:                c.Name,
		IDs:                 c.IDs(),
		Tags:                c.Tags,
		Filters:             blockedfiltersJSON,
		WhitelistFilter:     allowfiltersJSON,
		UseGlobalSettings:   !c.UseOwnSettings,
		UseGlobalFilters:    c.UseGlobalFilters,
		FilteringEnabled:    c.FilteringEnabled,
		ParentalEnabled:     c.ParentalEnabled,
		SafeSearchEnabled:   safeSearchConf.Enabled,
		SafeSearchConf:      safeSearchConf,
		SafeBrowsingEnabled: c.SafeBrowsingEnabled,

		UseGlobalBlockedServices: !c.UseOwnBlockedServices,

		Schedule:        c.BlockedServices.Schedule,
		BlockedServices: c.BlockedServices.IDs,

		Upstreams: c.Upstreams,

		IgnoreQueryLog:   aghalg.BoolToNullBool(c.IgnoreQueryLog),
		IgnoreStatistics: aghalg.BoolToNullBool(c.IgnoreStatistics),

		UpstreamsCacheSize:    c.UpstreamsCacheSize,
		UpstreamsCacheEnabled: aghalg.BoolToNullBool(c.UpstreamsCacheEnabled),
	}
}

func appendClientFilter(addedFiltersIndexs []int, filtersYAML []filtering.FilterYAML, clientName string) {
	if len(addedFiltersIndexs) > 0 {
		// Download new filter
		for index, fy := range filtersYAML {
			if slices.Contains(addedFiltersIndexs, index) {
				ok, _ := Context.filters.Update(&fy)
				if ok {
					names := map[string]string{}
					names[clientName] = fy.Name
					cfy := filtering.ClientFilterYAML{FilterYAML: &fy, Names: names}
					config.Filtering.ClientsFilters = append(config.Filtering.ClientsFilters, cfy)
				}
			}
		}
	}
}

// handleAddClient is the handler for POST /control/clients/add HTTP API.
func (clients *clientsContainer) handleAddClient(w http.ResponseWriter, r *http.Request) {
	cj := clientJSON{}
	err := json.NewDecoder(r.Body).Decode(&cj)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "failed to process request body: %s", err)

		return
	}

	c, err := clients.jsonToClient(cj, nil)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}
	emptyFilters := []filtering.FilterYAML{}
	var addedFiltersIndexs []int
	c.Filters, addedFiltersIndexs = clients.checkAndFilters(emptyFilters, c.Filters, c)
	var addedFiltersIndexsWhitelist []int
	c.WhitelistFilters, addedFiltersIndexsWhitelist = clients.checkAndFilters(emptyFilters, c.WhitelistFilters, c)
	appendClientFilter(addedFiltersIndexs, c.Filters, c.Name)
	appendClientFilter(addedFiltersIndexsWhitelist, c.WhitelistFilters, c.Name)

	ok, err := clients.add(c)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}

	if !ok {
		aghhttp.Error(r, w, http.StatusBadRequest, "Client already exists")

		return
	}

	onConfigModified()
}

// handleDelClient is the handler for POST /control/clients/delete HTTP API.
func (clients *clientsContainer) handleDelClient(w http.ResponseWriter, r *http.Request) {
	cj := clientJSON{}
	err := json.NewDecoder(r.Body).Decode(&cj)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "failed to process request body: %s", err)

		return
	}

	if len(cj.Name) == 0 {
		aghhttp.Error(r, w, http.StatusBadRequest, "client's name must be non-empty")

		return
	}

	if !clients.remove(cj.Name) {
		aghhttp.Error(r, w, http.StatusBadRequest, "Client not found")

		return
	}

	clients.bulkUpdateClientFilters(&cj.Name)

	onConfigModified()
}

// updateJSON contains the name and data of the updated persistent client.
type updateJSON struct {
	Name string     `json:"name"`
	Data clientJSON `json:"data"`
}

// Check filters exist in a list
func existsFilters(filter filtering.FilterYAML, listFilters []filtering.FilterYAML) (isExists bool, filterName string, isEnabled bool) {
	isExists = false
	for _, fj := range listFilters {
		if filter.ID == fj.ID {
			isExists = true
			filterName = fj.Name
			isEnabled = fj.Enabled
			break
		}
	}
	return isExists, filterName, isEnabled
}

func (clients *clientsContainer) checkAndFilters(
	oldFilters []filtering.FilterYAML,
	newFilters []filtering.FilterYAML,
	client *client.Persistent,
) (
	validFilters []filtering.FilterYAML,
	addedFiltersIndexs []int,
) {
	for _, fj := range newFilters {
		isExists, _, _ := existsFilters(fj, oldFilters)
		if !isExists {
			// Check filter exist in clients filters and add
			isExistInClientFilters := false
			for _, cfj := range config.ClientsFilters {
				if fj.URL == cfj.URL {
					validFilters = append(validFilters, *cfj.FilterYAML)
					cfj.Names[client.Name] = fj.Name
					isExistInClientFilters = true
					continue
				}
			}
			if isExistInClientFilters {
				continue
			}
			// Process add filter
			err := filtering.ValidateFilterURL(fj.URL)
			if err == nil {
				addedFiltersIndexs = append(addedFiltersIndexs, len(validFilters))
				validFilters = append(validFilters, fj)
			}
		} else {
			validFilters = append(validFilters, fj)
		}
	}
	Context.filters.LoadFilters(validFilters)
	return validFilters, addedFiltersIndexs
}

// bulkUpdateClientFilters delete or disable filter that does not used or enabled by any client
func (clients *clientsContainer) bulkUpdateClientFilters(delClientName *string) (hasDeletedFilter bool) {
	var needDeleteIdx []int
	for idx, fy := range config.Filtering.ClientsFilters {
		needDelete := true
		shoudEnable := false
		if delClientName != nil {
			delete(fy.Names, *delClientName)
		}
		for _, c := range clients.list {
			isExistFilters, filterName, isEnabled := existsFilters(*fy.FilterYAML, c.Filters)
			isExistWhitelistFilter, wFilterName, isEnabledWhiteList := existsFilters(*fy.FilterYAML, c.WhitelistFilters)
			if !isExistFilters && !isExistWhitelistFilter {
				delete(fy.Names, c.Name)
			} else {
				needDelete = false
				if isExistFilters {
					fy.Names[c.Name] = filterName
				}
				if isExistWhitelistFilter {
					fy.Names[c.Name] = wFilterName
				}
				shoudEnable = !c.UseGlobalFilters && (isEnabled || isEnabledWhiteList)
				continue
			}
		}
		if fy.Enabled != shoudEnable {
			fy.Enabled = shoudEnable
		}
		if needDelete {
			needDeleteIdx = append(needDeleteIdx, idx)
		}
	}
	for _, deleteIdx := range needDeleteIdx {
		deleted := config.Filtering.ClientsFilters[deleteIdx]
		config.Filtering.ClientsFilters = slices.Delete(config.Filtering.ClientsFilters, deleteIdx, deleteIdx+1)
		p := deleted.Path(config.Filtering.DataDir)
		os.Remove(p)
		hasDeletedFilter = true
	}
	return hasDeletedFilter
}

// handleUpdateClient is the handler for POST /control/clients/update HTTP API.
//
// TODO(s.chzhen):  Accept updated parameters instead of whole structure.
func (clients *clientsContainer) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	dj := updateJSON{}
	err := json.NewDecoder(r.Body).Decode(&dj)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "failed to process request body: %s", err)

		return
	}

	if len(dj.Name) == 0 {
		aghhttp.Error(r, w, http.StatusBadRequest, "Invalid request")

		return
	}

	var prev *client.Persistent
	var ok bool

	func() {
		clients.lock.Lock()
		defer clients.lock.Unlock()

		prev, ok = clients.list[dj.Name]
	}()

	if !ok {
		aghhttp.Error(r, w, http.StatusBadRequest, "client not found")

		return
	}

	c, err := clients.jsonToClient(dj.Data, prev)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}
	var addedFiltersIndexs []int
	c.Filters, addedFiltersIndexs = clients.checkAndFilters(prev.Filters, c.Filters, c)
	var addedFiltersIndexsWhitelist []int
	c.WhitelistFilters, addedFiltersIndexsWhitelist = clients.checkAndFilters(prev.WhitelistFilters, c.WhitelistFilters, c)
	appendClientFilter(addedFiltersIndexs, c.Filters, c.Name)
	appendClientFilter(addedFiltersIndexsWhitelist, c.WhitelistFilters, c.Name)

	err = clients.update(prev, c)
	if err != nil {
		aghhttp.Error(r, w, http.StatusBadRequest, "%s", err)

		return
	}
	clients.bulkUpdateClientFilters(nil)
	onConfigModified()
}

// handleFindClient is the handler for GET /control/clients/find HTTP API.
func (clients *clientsContainer) handleFindClient(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := []map[string]*clientJSON{}
	for i := 0; i < len(q); i++ {
		idStr := q.Get(fmt.Sprintf("ip%d", i))
		if idStr == "" {
			break
		}

		ip, _ := netip.ParseAddr(idStr)
		c, ok := clients.find(idStr)
		var cj *clientJSON
		if !ok {
			cj = clients.findRuntime(ip, idStr)
		} else {
			cj = clientToJSON(c)
			disallowed, rule := clients.dnsServer.IsBlockedClient(ip, idStr)
			cj.Disallowed, cj.DisallowedRule = &disallowed, &rule
		}

		data = append(data, map[string]*clientJSON{
			idStr: cj,
		})
	}

	aghhttp.WriteJSONResponseOK(w, r, data)
}

// findRuntime looks up the IP in runtime and temporary storages, like
// /etc/hosts tables, DHCP leases, or blocklists.  cj is guaranteed to be
// non-nil.
func (clients *clientsContainer) findRuntime(ip netip.Addr, idStr string) (cj *clientJSON) {
	rc, ok := clients.findRuntimeClient(ip)
	if !ok {
		// It is still possible that the IP used to be in the runtime clients
		// list, but then the server was reloaded.  So, check the DNS server's
		// blocked IP list.
		//
		// See https://github.com/AdguardTeam/AdGuardHome/issues/2428.
		disallowed, rule := clients.dnsServer.IsBlockedClient(ip, idStr)
		cj = &clientJSON{
			IDs:            []string{idStr},
			Disallowed:     &disallowed,
			DisallowedRule: &rule,
			WHOIS:          &whois.Info{},
		}

		return cj
	}

	_, host := rc.Info()
	cj = &clientJSON{
		Name:  host,
		IDs:   []string{idStr},
		WHOIS: whoisOrEmpty(rc),
	}

	disallowed, rule := clients.dnsServer.IsBlockedClient(ip, idStr)
	cj.Disallowed, cj.DisallowedRule = &disallowed, &rule

	return cj
}

// RegisterClientsHandlers registers HTTP handlers
func (clients *clientsContainer) registerWebHandlers() {
	httpRegister(http.MethodGet, "/control/clients", clients.handleGetClients)
	httpRegister(http.MethodGet, "/control/client/detail", clients.handleGetClient)
	httpRegister(http.MethodPost, "/control/clients/add", clients.handleAddClient)
	httpRegister(http.MethodPost, "/control/clients/delete", clients.handleDelClient)
	httpRegister(http.MethodPost, "/control/clients/update", clients.handleUpdateClient)
	httpRegister(http.MethodGet, "/control/clients/find", clients.handleFindClient)
}

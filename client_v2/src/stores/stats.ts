import { createStore, unwrap } from 'solid-js/store';
import { untrack } from 'solid-js';
import {
    stats,
    getStatsConfig as fetchStatsConfig,
    putStatsConfig,
    statsReset,
    clientsSearch,
} from 'panel/api/generated';
import { addErrorToast, addSuccessToast } from './toasts';
import intl from 'panel/common/intl';
import {
    DAY,
    HOUR,
    STATS_INTERVALS_DAYS,
    TIME_UNITS,
    TOP_CLIENTS_VISIBLE_ITEMS,
} from 'panel/helpers/constants';
import { clampStatsPeriod } from 'panel/helpers/statistics';
import {
    normalizeTopStats,
    normalizeTopClients,
    addClientInfo,
    getParamsForClientsSearch,
    secondsToMilliseconds,
} from 'panel/helpers/helpers';
import type { GetStatsConfigResponse } from 'panel/api/model/getStatsConfigResponse';
import type { ClientFindSubEntry } from 'panel/api/model/clientFindSubEntry';
import type { ClientsFindEntry } from 'panel/api/model/clientsFindEntry';

type StatsState = {
    processingGetConfig: boolean;
    processingSetConfig: boolean;
    processingStats: boolean;
    processingReset: boolean;
    processingClientInfo: boolean;
    /** Whether the stats config (interval etc.) has been fetched from the server. */
    configLoaded: boolean;
    /** Whether a stats-config request has settled, successfully or not. */
    configInitialized: boolean;
    /** Whether a stats request has settled, successfully or not. */
    statsInitialized: boolean;
    interval: number;
    customInterval: number | null;
    dnsQueries: number[];
    blockedFiltering: number[];
    replacedParental: number[];
    replacedSafebrowsing: number[];
    topBlockedDomains: { name: string; count: number }[];
    topClients: { name: string; count: number; info: ClientFindSubEntry }[];
    /** Request counts for the clients in `topClients`, keyed by client ID. */
    normalizedTopClients: Record<string, number>;
    topQueriedDomains: { name: string; count: number }[];
    numBlockedFiltering: number;
    numDnsQueries: number;
    numReplacedParental: number;
    numReplacedSafebrowsing: number;
    numReplacedSafesearch: number;
    avgProcessingTime: number;
    timeUnits: string;
    enabled: boolean;
    topUpstreamsAvgTime: { name: string; count: number }[];
    topUpstreamsResponses: { name: string; count: number }[];
    ignored: string[];
    ignored_enabled: boolean;
};

const initialState: StatsState = {
    processingGetConfig: false,
    processingSetConfig: false,
    processingStats: true,
    processingReset: false,
    processingClientInfo: false,
    configLoaded: false,
    configInitialized: false,
    statsInitialized: false,
    interval: DAY,
    customInterval: null,
    dnsQueries: [],
    blockedFiltering: [],
    replacedParental: [],
    replacedSafebrowsing: [],
    topBlockedDomains: [],
    topClients: [],
    normalizedTopClients: {},
    topQueriedDomains: [],
    numBlockedFiltering: 0,
    numDnsQueries: 0,
    numReplacedParental: 0,
    numReplacedSafebrowsing: 0,
    numReplacedSafesearch: 0,
    avgProcessingTime: 0,
    timeUnits: TIME_UNITS?.HOURS || 'hours',
    enabled: true,
    topUpstreamsAvgTime: [],
    topUpstreamsResponses: [],
    ignored: [],
    ignored_enabled: false,
};

const [state, setState] = createStore<StatsState>(initialState);

// Guards against a slower stats request overwriting a newer stats snapshot.
let statsSequence = 0;

/**
 * Client info resolved for the rows currently displayed on the Top clients
 * page, keyed by client ID.  Pages enrich rows on demand, so paging back and
 * forth must not send the same IDs to the backend again.
 *
 * The cache is cleared on every stats refresh, but in-flight requests are
 * kept so an enrichment started before the refresh is not requested twice.
 */
let clientInfoCache = new Map<string, ClientFindSubEntry>();
/** IDs with a client-info request in flight, mapped to that request's ID. */
const clientInfoInFlight = new Map<string, number>();
let clientInfoRequestId = 0;

const resetClientInfoCache = () => {
    clientInfoCache = new Map();
};

const cacheClientInfo = (clients: ClientsFindEntry[], ids: string[]): void => {
    const found = new Map<string, ClientFindSubEntry>();
    clients.forEach((entry) => {
        ids.forEach((id) => {
            const info = entry[id];
            if (info) {
                found.set(id, info);
            }
        });
    });
    ids.forEach((id) => clientInfoCache.set(id, found.get(id) ?? {}));
};

type TopClient = StatsState['topClients'][number];

/**
 * Folds already-resolved client info into a top-clients list.
 *
 * A stats refresh and the client search run concurrently and either may finish
 * first.  Both writers must therefore consult the cache: otherwise a fast
 * search merges its info into the previous list, the stats response then
 * replaces the list with empty info, and the now-cached IDs prevent the page
 * from ever requesting them again.
 */
const withResolvedClientInfo = (clients: TopClient[]): TopClient[] =>
    clients.map((client) => {
        const info = clientInfoCache.get(client.name);
        // The store returns proxies, so compare the underlying object.
        return info && unwrap(client.info) !== info ? { ...client, info } : client;
    });

/**
 * Re-applies cached client info to the rows currently in the store.  Does
 * nothing when every row already carries the cached info, so repeated calls
 * from the page's visible-rows effect cannot loop.
 */
const applyResolvedClientInfo = (): void => {
    const topClients = withResolvedClientInfo(state.topClients);
    if (topClients.every((client, index) => client === state.topClients[index])) {
        return;
    }

    setState({
        topClients,
        normalizedTopClients: normalizeTopClients(topClients),
    });
};

/**
 * Fetches statistics and optionally enriches the top clients with client info
 * (names, WHOIS, blocked status) via `POST /control/clients/search`.
 *
 * @param period Stats period in milliseconds.
 * @param enrichClientsLimit How many top clients to request client info for.
 * The dashboard renders only `TOP_CLIENTS_VISIBLE_ITEMS` rows, so by default
 * only those are looked up.  Pass an explicit limit when more rows need
 * enrichment.  Pass `0` to skip the lookup entirely and use `enrichTopClients`
 * for the rows a page actually displays.
 */
export const getStats = async (
    period?: number,
    enrichClientsLimit: number = TOP_CLIENTS_VISIBLE_ITEMS,
) => {
    setState({ processingStats: true, processingClientInfo: false });
    const sequence = ++statsSequence;
    resetClientInfoCache();
    try {
        // Clamp by the real retention so callers don't have to know it.
        const data = await stats(
            period != null ? { recent: clampStatsPeriod(period, state.interval) } : undefined,
        );

        const normalizedTopClientsList = normalizeTopStats(data.top_clients || []);
        const topClientsToEnrich = normalizedTopClientsList.slice(0, enrichClientsLimit);
        const idsToEnrich = topClientsToEnrich.map((client) => client.name);
        const clientsPromise = idsToEnrich.length
            ? clientsSearch(getParamsForClientsSearch(topClientsToEnrich, 'name'))
            : null;

        // Render stats right away; client info arrives asynchronously.  Info
        // resolved while the stats request was running is folded in here so a
        // fast client search is not lost.
        const topClientsWithEmptyInfo = withResolvedClientInfo(
            addClientInfo(normalizedTopClientsList, [], 'name'),
        );

        setState({
            dnsQueries: data.dns_queries || [],
            blockedFiltering: data.blocked_filtering || [],
            replacedParental: data.replaced_parental || [],
            replacedSafebrowsing: data.replaced_safebrowsing || [],
            topBlockedDomains: normalizeTopStats(data.top_blocked_domains || []),
            topClients: topClientsWithEmptyInfo,
            normalizedTopClients: normalizeTopClients(topClientsWithEmptyInfo),
            topQueriedDomains: normalizeTopStats(data.top_queried_domains || []),
            numBlockedFiltering: data.num_blocked_filtering || 0,
            numDnsQueries: data.num_dns_queries || 0,
            numReplacedParental: data.num_replaced_parental || 0,
            numReplacedSafebrowsing: data.num_replaced_safebrowsing || 0,
            numReplacedSafesearch: data.num_replaced_safesearch || 0,
            avgProcessingTime: secondsToMilliseconds(data.avg_processing_time),
            timeUnits: data.time_units || initialState.timeUnits,
            topUpstreamsAvgTime: normalizeTopStats(data.top_upstreams_avg_time || []).map(
                (item: { name: string; count: number }) => ({
                    ...item,
                    count: secondsToMilliseconds(item.count),
                }),
            ),
            topUpstreamsResponses: normalizeTopStats(data.top_upstreams_responses || []),
            processingStats: false,
            processingClientInfo: clientsPromise !== null,
            statsInitialized: true,
        });

        if (clientsPromise === null) {
            return;
        }

        try {
            const clients = await clientsPromise;
            if (sequence !== statsSequence) {
                return;
            }
            cacheClientInfo(clients, idsToEnrich);
            // Use the live rows, not the local snapshot: the page may have
            // merged info for other rows while this request was in flight.
            const topClientsWithInfo = withResolvedClientInfo(state.topClients);
            setState({
                topClients: topClientsWithInfo,
                normalizedTopClients: normalizeTopClients(topClientsWithInfo),
                processingClientInfo: false,
            });
        } catch (error) {
            if (sequence !== statsSequence) {
                return;
            }
            addErrorToast({ error });
            setState('processingClientInfo', false);
        }
    } catch (error) {
        addErrorToast({ error });
        setState({ processingStats: false, statsInitialized: true });
    }
};

/**
 * Fetches client info for specific top clients and merges it into
 * `topClients`.
 *
 * The Top clients page calls this with the rows of the current table page
 * instead of enriching every top client up front.  Resolved IDs are cached
 * until the next `getStats`.
 *
 * Client info is keyed by client ID and does not depend on the stats
 * snapshot, so a response is applied even when a newer stats refresh has
 * started in the meantime.
 *
 * @param ids Client IDs (IP addresses, CIDRs, MAC addresses, or ClientIDs).
 */
export const enrichTopClients = async (ids: string[]): Promise<void> => {
    const uniqueIds = [...new Set(ids)];
    if (uniqueIds.length === 0) {
        return;
    }

    const missing = uniqueIds.filter(
        (id) => !clientInfoCache.has(id) && !clientInfoInFlight.has(id),
    );

    if (missing.length === 0) {
        // Cached already, but a stats refresh may have replaced the rows with
        // empty info in the meantime.
        applyResolvedClientInfo();
        return;
    }

    const requestId = ++clientInfoRequestId;
    missing.forEach((id) => clientInfoInFlight.set(id, requestId));
    setState('processingClientInfo', true);

    try {
        const clients = await clientsSearch({
            clients: missing.map((id) => ({ id })),
        });

        cacheClientInfo(clients, missing);
        applyResolvedClientInfo();
    } catch (error) {
        addErrorToast({ error });
    } finally {
        missing.forEach((id) => {
            if (clientInfoInFlight.get(id) === requestId) {
                clientInfoInFlight.delete(id);
            }
        });
        setState('processingClientInfo', clientInfoInFlight.size > 0);
    }
};

export const getStatsConfig = async () => {
    setState('processingGetConfig', true);
    try {
        const data = await fetchStatsConfig();
        setState({
            interval: data.interval || DAY,
            enabled: data.enabled ?? true,
            customInterval: !STATS_INTERVALS_DAYS.includes(data.interval)
                ? data.interval / HOUR
                : null,
            ignored: data.ignored || [],
            ignored_enabled: data.ignored_enabled ?? false,
            processingGetConfig: false,
            configLoaded: true,
            configInitialized: true,
        });
    } catch (error) {
        addErrorToast({ error });
        setState({ processingGetConfig: false, configInitialized: true });
    }
};

export const setStatsConfig = async (values: GetStatsConfigResponse): Promise<boolean> => {
    setState('processingSetConfig', true);
    try {
        await putStatsConfig(values);
        setState({ ...values, processingSetConfig: false });
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState('processingSetConfig', false);
        return false;
    }
};

export const enableStatistics = async (period?: number): Promise<boolean> => {
    const result = await setStatsConfig({
        enabled: true,
        interval: state.interval,
        ignored: state.ignored,
        ignored_enabled: state.ignored_enabled,
    });
    if (result) {
        await getStats(period);
    }
    return result;
};

export const resetStats = async () => {
    setState('processingReset', true);
    try {
        await statsReset();
        setState('processingReset', false);
        addSuccessToast(intl.getMessage('settings_notify_statistics_cleared'));
        await getStats();
    } catch (error) {
        addErrorToast({ error });
        setState('processingReset', false);
    }
};

export const statsState = untrack(() => state);

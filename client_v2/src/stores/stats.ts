import { createStore } from 'solid-js/store';
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
import {
    normalizeTopStats,
    normalizeTopClients,
    addClientInfo,
    getParamsForClientsSearch,
    secondsToMilliseconds,
} from 'panel/helpers/helpers';
import type { GetStatsConfigResponse } from 'panel/api/model/getStatsConfigResponse';
import type { ClientFindSubEntry } from 'panel/api/model/clientFindSubEntry';

type StatsState = {
    processingGetConfig: boolean;
    processingSetConfig: boolean;
    processingStats: boolean;
    processingReset: boolean;
    processingClientInfo: boolean;
    /** Whether the stats config (interval etc.) has been fetched from the server. */
    configLoaded: boolean;
    interval: number;
    customInterval: number | null;
    dnsQueries: number[];
    blockedFiltering: number[];
    replacedParental: number[];
    replacedSafebrowsing: number[];
    topBlockedDomains: { name: string; count: number }[];
    topClients: { name: string; count: number; info: ClientFindSubEntry }[];
    normalizedTopClients: {
        auto: Record<string, number>;
        configured: Record<string, number>;
    };
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
    interval: DAY,
    customInterval: null,
    dnsQueries: [],
    blockedFiltering: [],
    replacedParental: [],
    replacedSafebrowsing: [],
    topBlockedDomains: [],
    topClients: [],
    normalizedTopClients: { auto: {}, configured: {} },
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

// Guards against stale client-info updates overwriting a newer stats refresh.
let statsSequence = 0;

/**
 * Fetches statistics and optionally enriches the top clients with client info
 * (names, WHOIS, blocked status) via `POST /control/clients/search`.
 *
 * @param period Stats period in milliseconds.
 * @param enrichClientsLimit How many top clients to request client info for.
 * The dashboard renders only `TOP_CLIENTS_VISIBLE_ITEMS` rows, so by default
 * only those are looked up.  Pass `STATS_TOP_CLIENTS_LIMIT` when all top
 * clients must be enriched (the "Show more" Top clients page and the Clients
 * page, which aggregates per-client query counts by resolved name).
 */
export const getStats = async (
    period?: number,
    enrichClientsLimit: number = TOP_CLIENTS_VISIBLE_ITEMS,
) => {
    setState('processingStats', true);
    const sequence = ++statsSequence;
    try {
        const data = await stats(period != null ? { recent: period } : undefined);

        const normalizedTopClientsList = normalizeTopStats(data.top_clients || []);
        const topClientsToEnrich = normalizedTopClientsList.slice(0, enrichClientsLimit);
        const clientsParams = getParamsForClientsSearch(topClientsToEnrich, 'name');
        const clientsPromise = clientsSearch(clientsParams);

        // Render stats right away; client info arrives asynchronously.
        const topClientsWithEmptyInfo = addClientInfo(normalizedTopClientsList, [], 'name');

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
            processingClientInfo: true,
        });

        try {
            const clients = await clientsPromise;
            if (sequence !== statsSequence) {
                return;
            }
            const topClientsWithInfo = addClientInfo(normalizedTopClientsList, clients, 'name');
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
        setState('processingStats', false);
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
        });
    } catch (error) {
        addErrorToast({ error });
        setState('processingGetConfig', false);
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

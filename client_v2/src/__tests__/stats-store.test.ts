import { describe, it, expect, vi, beforeEach } from 'vitest';

const mocks = vi.hoisted(() => ({
    stats: vi.fn(),
    getStatsConfig: vi.fn(),
    putStatsConfig: vi.fn(),
    statsReset: vi.fn(),
    clientsSearch: vi.fn(),
    addErrorToast: vi.fn(),
    addSuccessToast: vi.fn(),
}));

vi.mock('panel/api/generated', () => ({
    stats: mocks.stats,
    getStatsConfig: mocks.getStatsConfig,
    putStatsConfig: mocks.putStatsConfig,
    statsReset: mocks.statsReset,
    clientsSearch: mocks.clientsSearch,
}));
vi.mock('panel/stores/toasts', () => ({
    addErrorToast: mocks.addErrorToast,
    addSuccessToast: mocks.addSuccessToast,
}));
vi.mock('panel/common/intl', () => ({
    default: { getMessage: vi.fn() },
}));

import { DAY } from 'panel/helpers/constants';

import { getStats, getStatsConfig, statsState } from 'panel/stores/stats';

describe('getStats', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mocks.clientsSearch.mockResolvedValue([]);
        mocks.stats.mockResolvedValue({});
    });

    it('clamps the requested period by the configured stats interval', async () => {
        await getStats(DAY * 30);
        expect(mocks.stats).toHaveBeenCalledWith({ recent: DAY });

        // A smaller period is passed through untouched.
        await getStats(6 * 60 * 60 * 1000);
        expect(mocks.stats).toHaveBeenCalledWith({ recent: 6 * 60 * 60 * 1000 });
    });

    it('calls the API without params when no period is given', async () => {
        await getStats();
        expect(mocks.stats).toHaveBeenCalledWith(undefined);
    });

    it('marks statsAttempted after a successful stats request', async () => {
        await getStats();
        expect(statsState.statsAttempted).toBe(true);
    });

    it('marks statsAttempted after a failed stats request', async () => {
        mocks.stats.mockRejectedValue(new Error('network'));
        await getStats();
        expect(statsState.statsAttempted).toBe(true);
        expect(mocks.addErrorToast).toHaveBeenCalled();
    });

    it('enriches top clients and stores normalizedTopClients', async () => {
        mocks.stats.mockResolvedValue({
            top_clients: [{ '1.2.3.4': 5 }],
            avg_processing_time: 0.012,
            top_blocked_domains: [],
            top_queried_domains: [],
            top_upstreams_avg_time: [],
            top_upstreams_responses: [],
        });

        await getStats();

        // searchClients was called with discovered client ids
        expect(mocks.clientsSearch).toHaveBeenCalledWith({
            clients: [{ id: '1.2.3.4' }],
        });
        // normalizedTopClients is populated (configured bucket carries info name)
        expect(Object.keys(statsState.normalizedTopClients.auto)).toContain('1.2.3.4');
    });

    it('converts avg_processing_time to milliseconds, falsy passthrough', async () => {
        mocks.stats.mockResolvedValue({ avg_processing_time: 0.012 });
        await getStats();
        expect(statsState.avgProcessingTime).toBe(12);

        mocks.stats.mockResolvedValue({ avg_processing_time: 0 });
        await getStats();
        expect(statsState.avgProcessingTime).toBe(0); // not NaN
    });

    it('converts top_upstreams_avg_time entries from seconds to milliseconds', async () => {
        mocks.stats.mockResolvedValue({
            top_upstreams_avg_time: [{ '1.1.1.1': 0.012 }, { '9.9.9.9': 0.3 }],
            top_clients: [],
            avg_processing_time: 0,
            top_blocked_domains: [],
            top_queried_domains: [],
            top_upstreams_responses: [],
        });

        await getStats();

        expect(statsState.topUpstreamsAvgTime).toEqual([
            { name: '1.1.1.1', count: 12 },
            { name: '9.9.9.9', count: 300 },
        ]);
    });

    it('renders stats before the client search resolves', async () => {
        let resolveSearch!: (value: unknown) => void;
        const deferred = new Promise((resolve) => {
            resolveSearch = resolve;
        });
        mocks.clientsSearch.mockReturnValueOnce(deferred as never);
        mocks.stats.mockResolvedValue({
            top_clients: [{ '1.2.3.4': 5 }],
            avg_processing_time: 0.012,
            top_blocked_domains: [],
            top_queried_domains: [],
            top_upstreams_avg_time: [],
            top_upstreams_responses: [],
        });

        const promise = getStats();
        // Let stats resolve; the client search is still pending.
        await Promise.resolve();

        expect(statsState.processingClientInfo).toBe(true);
        expect(statsState.topClients[0].info).toEqual({});
        expect(mocks.clientsSearch).toHaveBeenCalledWith({
            clients: [{ id: '1.2.3.4' }],
        });

        resolveSearch([{ '1.2.3.4': { name: 'My Phone' } }]);
        await promise;

        expect(statsState.processingClientInfo).toBe(false);
        expect(statsState.topClients[0].info).toEqual({ name: 'My Phone' });
    });

    it('ignores a stale client-info response when a newer refresh started', async () => {
        let resolveFirst!: (value: unknown) => void;
        const firstDeferred = new Promise((resolve) => {
            resolveFirst = resolve;
        });
        mocks.clientsSearch
            .mockReturnValueOnce(firstDeferred as never)
            .mockResolvedValue([]);
        mocks.stats.mockResolvedValue({
            top_clients: [{ '1.2.3.4': 5 }],
            avg_processing_time: 0.012,
            top_blocked_domains: [],
            top_queried_domains: [],
            top_upstreams_avg_time: [],
            top_upstreams_responses: [],
        });

        const first = getStats();
        await Promise.resolve();
        // Second refresh fully completes while the first search is still pending.
        await getStats();

        resolveFirst([{ '1.2.3.4': { name: 'Stale' } }]);
        await first;

        expect(statsState.processingClientInfo).toBe(false);
        expect(statsState.topClients[0].info).not.toEqual({ name: 'Stale' });
    });

    it('only requests client info for the dashboard-visible top clients by default', async () => {
        mocks.stats.mockResolvedValue({
            top_clients: Array.from({ length: 100 }, (_, i) => ({
                [`10.0.0.${i + 1}`]: 100 - i,
            })),
            avg_processing_time: 0.012,
            top_blocked_domains: [],
            top_queried_domains: [],
            top_upstreams_avg_time: [],
            top_upstreams_responses: [],
        });

        await getStats();

        expect(mocks.clientsSearch).toHaveBeenCalledTimes(1);
        expect(mocks.clientsSearch).toHaveBeenCalledWith({
            clients: [
                { id: '10.0.0.1' },
                { id: '10.0.0.2' },
                { id: '10.0.0.3' },
                { id: '10.0.0.4' },
            ],
        });
    });

    it('enriches all top clients when an explicit limit is passed', async () => {
        mocks.stats.mockResolvedValue({
            top_clients: Array.from({ length: 5 }, (_, i) => ({
                [`10.0.0.${i + 1}`]: 100 - i,
            })),
            avg_processing_time: 0.012,
            top_blocked_domains: [],
            top_queried_domains: [],
            top_upstreams_avg_time: [],
            top_upstreams_responses: [],
        });

        await getStats(undefined, 100);

        expect(mocks.clientsSearch).toHaveBeenCalledWith({
            clients: [
                { id: '10.0.0.1' },
                { id: '10.0.0.2' },
                { id: '10.0.0.3' },
                { id: '10.0.0.4' },
                { id: '10.0.0.5' },
            ],
        });
    });
});

describe('getStatsConfig', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('marks configAttempted but not configLoaded on failure', async () => {
        mocks.getStatsConfig.mockRejectedValue(new Error('network'));

        await getStatsConfig();

        expect(statsState.configAttempted).toBe(true);
        expect(statsState.configLoaded).toBe(false);
        expect(mocks.addErrorToast).toHaveBeenCalled();
    });

    it('marks configLoaded and configAttempted on success', async () => {
        mocks.getStatsConfig.mockResolvedValue({ interval: DAY * 30, enabled: true });

        await getStatsConfig();

        expect(statsState.configLoaded).toBe(true);
        expect(statsState.configAttempted).toBe(true);
        expect(statsState.interval).toBe(DAY * 30);
    });
});

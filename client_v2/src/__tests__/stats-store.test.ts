import { describe, it, expect, vi, beforeEach } from 'vitest';

const mocks = vi.hoisted(() => ({
    stats: vi.fn(),
    clientsSearch: vi.fn(),
    addErrorToast: vi.fn(),
}));

vi.mock('panel/api/generated', () => ({
    stats: mocks.stats,
    clientsSearch: mocks.clientsSearch,
}));
vi.mock('panel/stores/toasts', () => ({
    addErrorToast: mocks.addErrorToast,
}));

import { getStats, statsState } from 'panel/stores/stats';

describe('getStats', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mocks.clientsSearch.mockResolvedValue([]);
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
});

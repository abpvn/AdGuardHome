import { describe, expect, it, vi, beforeEach } from 'vitest';
import { getAdditionalLogs, setFilteredLogs, queryLogsState } from 'panel/stores/queryLogs';
import { queryLog, getQueryLogUrl } from 'panel/api/generated';

vi.mock('panel/api/generated', () => ({
    queryLog: vi.fn(),
    getQueryLogUrl: (params?: Record<string, unknown>) => {
        const normalizedParams = new URLSearchParams();
        Object.entries(params || {}).forEach(([key, value]) => {
            if (value !== undefined) {
                normalizedParams.append(key, String(value));
            }
        });
        const stringifiedParams = normalizedParams.toString();
        return stringifiedParams.length > 0
            ? `control/querylog?${stringifiedParams}`
            : 'control/querylog';
    },
}));

vi.mock('panel/stores/toasts', () => ({
    addErrorToast: vi.fn(),
    addSuccessToast: vi.fn(),
}));

describe('queryLogs store', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('getAdditionalLogs appends filtered rows using the oldest cursor and filter', async () => {
        (queryLog as any).mockReset();

        // Seed state: a full first page (20 rewritten) with more behind it.
        const fullPage = Array.from({ length: 20 }, () => ({
            reason: 'Rewrite',
            question: {},
        }));
        (queryLog as any).mockResolvedValueOnce({
            data: fullPage,
            oldest: 'cur',
        });
        await setFilteredLogs({ search: '', status: 'rewritten', reason: 'all', client: '' });
        expect(queryLogsState.isEntireLog).toBe(false);
        expect(queryLogsState.logs).toHaveLength(20);

        // Load more: one extra rewritten entry, then end of log.
        (queryLog as any).mockResolvedValueOnce({
            data: [{ reason: 'Rewrite', question: {} }],
            oldest: '',
        });

        await getAdditionalLogs();

        // The load-more request must carry the cursor and the reason filter.
        expect(queryLog).toHaveBeenLastCalledWith(
            expect.objectContaining({
                older_than: 'cur',
                reason: expect.arrayContaining([
                    'Rewrite',
                    'RewriteEtcHosts',
                    'RewriteRule',
                    'FilteredSafeSearch',
                ]),
            }),
        );
        // Must NOT send the deprecated response_status
        const lastCall = (queryLog as any).mock.calls.at(-1)[0];
        expect(lastCall).not.toHaveProperty('response_status');

        expect(queryLogsState.logs).toHaveLength(21);
        expect(queryLogsState.isEntireLog).toBe(true);
        expect(queryLogsState.processingAdditionalLogs).toBe(false);
    });

    it('setFilteredLogs sends reason strings for blocked status', async () => {
        (queryLog as any).mockReset();
        (queryLog as any).mockResolvedValue({
            data: [{ reason: 'FilteredBlackList', question: {} }],
            oldest: '',
        });

        await setFilteredLogs({ search: '', status: 'blocked', reason: 'all', client: '' });

        const lastCall = (queryLog as any).mock.calls.at(-1)[0];
        expect(queryLog).toHaveBeenLastCalledWith(
            expect.objectContaining({
                reason: expect.arrayContaining([
                    'FilteredBlackList',
                    'FilteredSafeBrowsing',
                    'FilteredParental',
                    'FilteredBlockedService',
                ]),
            }),
        );
        expect(lastCall).not.toHaveProperty('response_status');
    });

    it('setFilteredLogs sends the client filter to the API', async () => {
        (queryLog as any).mockReset();
        (queryLog as any).mockResolvedValue({
            data: [{ reason: 'NotFilteredNotFound', question: {} }],
            oldest: '',
        });

        await setFilteredLogs({
            search: '',
            status: 'all',
            reason: 'all',
            client: 'My Phone',
        });

        const lastCall = (queryLog as any).mock.calls.at(-1)[0];
        expect(lastCall).toHaveProperty('client', 'My Phone');
    });

    it('omits the client param when no client filter is active', async () => {
        (queryLog as any).mockReset();
        (queryLog as any).mockResolvedValue({
            data: [{ reason: 'NotFilteredNotFound', question: {} }],
            oldest: '',
        });

        await setFilteredLogs({ search: '', status: 'all', reason: 'all', client: '' });

        const lastCall = (queryLog as any).mock.calls.at(-1)[0];
        expect(getQueryLogUrl(lastCall)).not.toContain('client=');
    });

    it('does not mark the log as complete when additional loading stops', async () => {
        (queryLog as any).mockResolvedValue({
            data: [],
            oldest: 'next-cursor',
        });

        await getAdditionalLogs();

        expect(queryLogsState.processingAdditionalLogs).toBe(false);
        expect(queryLogsState.isEntireLog).toBe(false);
    });

    it('accumulates pages until oldest is empty (short-polling)', async () => {
        (queryLog as any)
            .mockResolvedValueOnce({
                data: [{ reason: 'Rewrite' }],
                oldest: 'cur',
                is_entire_log: false,
            })
            .mockResolvedValueOnce({
                data: [{ reason: 'Rewrite' }],
                oldest: '',
                is_entire_log: true,
            });

        await setFilteredLogs({ search: '', status: 'rewritten', reason: 'all', client: '' });
        expect(queryLog).toHaveBeenCalledTimes(2);
        expect(queryLogsState.processingGetLogs).toBe(false);
    });

    it('always sends limit=20 to prevent loading all records at once', async () => {
        (queryLog as any).mockReset();
        (queryLog as any)
            .mockResolvedValueOnce({
                data: Array.from({ length: 20 }, () => ({ reason: 'Rewrite', question: {} })),
                oldest: 'cursor1',
            })
            .mockResolvedValueOnce({
                data: [{ reason: 'Rewrite', question: {} }],
                oldest: '',
            });

        await setFilteredLogs({ search: '', status: 'rewritten', reason: 'all', client: '' });

        for (const call of (queryLog as any).mock.calls) {
            expect(call[0]).toHaveProperty('limit', 20);
        }
        expect(queryLog).not.toHaveBeenCalledWith(expect.not.objectContaining({ limit: 20 }));

        (queryLog as any).mockReset();
        (queryLog as any).mockResolvedValueOnce({
            data: [{ reason: 'Rewrite', question: {} }],
            oldest: '',
        });

        await getAdditionalLogs();

        expect(queryLog).toHaveBeenCalledWith(expect.objectContaining({ limit: 20 }));
    });
});

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockReload = vi.fn();

Object.defineProperty(window, 'location', {
    value: { reload: mockReload },
    writable: true,
});

const mockBeginUpdate = vi.fn();
const mockGetVersionJson = vi.fn();
const mockAddNoticeToast = vi.fn();
const mockGetUpdateFailedMessage = vi.fn(() => 'update_failed');
const mockGetTlsStatus = vi.fn();
let mockStatusQueue: unknown[] = [];

vi.mock('panel/api/generated', () => ({
    getStatusUrl: () => 'control/status',
    getVersionJson: () => mockGetVersionJson(),
    beginUpdate: () => mockBeginUpdate(),
    setProtection: vi.fn(),
    clientsStatus: vi.fn(),
    getProfile: vi.fn(),
    updateProfile: vi.fn(),
}));

vi.mock('panel/api/customFetch', () => ({
    customFetch: () => {
        const next = mockStatusQueue.shift();
        if (next instanceof Error) {
            return Promise.reject(next);
        }
        return Promise.resolve(next);
    },
}));

vi.mock('panel/common/intl', () => ({
    default: { getMessage: (key: string) => key },
}));

vi.mock('../../stores/encryption', () => ({
    getTlsStatus: () => mockGetTlsStatus(),
}));

vi.mock('../../stores/toasts', () => ({
    addErrorToast: vi.fn(),
    addSuccessToast: vi.fn(),
    addNoticeToast: () => mockAddNoticeToast(),
}));

vi.mock('../../stores/dashboard/noticeOptions', () => ({
    getUpdateFailedMessage: () => mockGetUpdateFailedMessage(),
}));

import { getDnsStatus, getUpdate, dashboardState } from 'panel/stores/dashboard';

const makeStatus = (overrides: Record<string, unknown> = {}) => ({
    dns_addresses: ['127.0.0.1'],
    dns_port: 53,
    http_port: 80,
    protection_enabled: true,
    protection_disabled_duration: 0,
    running: true,
    version: 'v0.1.0',
    language: 'en',
    start_time: 111,
    ...overrides,
});

const flushMicrotasks = async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
};

const seedStatus = async (status: Record<string, unknown>) => {
    mockStatusQueue = [status];
    await getDnsStatus();
    await flushMicrotasks();
};

describe('stores/dashboard getUpdate', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        mockStatusQueue = [];
        mockReload.mockClear();
        mockBeginUpdate.mockReset();
        mockGetVersionJson.mockReset();
        mockAddNoticeToast.mockClear();
    });

    afterEach(() => {
        vi.clearAllTimers();
        vi.useRealTimers();
    });

    it('keeps polling while the status is unchanged and reloads after a restart with the same version', async () => {
        await seedStatus(makeStatus({ version: 'v0.1.0', start_time: 111 }));

        mockStatusQueue = [
            makeStatus({ version: 'v0.1.0', start_time: 111 }),
            makeStatus({ version: 'v0.1.0', start_time: 222 }),
        ];
        mockBeginUpdate.mockResolvedValue(undefined);

        await getUpdate();
        await flushMicrotasks();

        expect(mockReload).not.toHaveBeenCalled();

        await vi.advanceTimersByTimeAsync(1000);

        expect(mockReload).toHaveBeenCalledTimes(1);
        expect(dashboardState.processingUpdate).toBe(false);
    });

    it('reloads as soon as the version changes', async () => {
        await seedStatus(makeStatus({ version: 'v0.1.0', start_time: 111 }));

        mockStatusQueue = [makeStatus({ version: 'v0.2.0', start_time: 999 })];
        mockBeginUpdate.mockResolvedValue(undefined);

        await getUpdate();
        await flushMicrotasks();

        expect(mockReload).toHaveBeenCalledTimes(1);
        expect(dashboardState.processingUpdate).toBe(false);
    });

    it('keeps polling while the server is restarting (connection errors)', async () => {
        await seedStatus(makeStatus({ version: 'v0.1.0', start_time: 111 }));

        mockStatusQueue = [
            new Error('connection refused'),
            new Error('connection refused'),
            makeStatus({ version: 'v0.2.0', start_time: 999 }),
        ];
        mockBeginUpdate.mockResolvedValue(undefined);

        await getUpdate();
        await flushMicrotasks();
        await vi.advanceTimersByTimeAsync(1000);
        await vi.advanceTimersByTimeAsync(1000);

        expect(mockReload).toHaveBeenCalledTimes(1);
        expect(dashboardState.processingUpdate).toBe(false);
    });

    it('shows a notice and resets the flag when the update request fails', async () => {
        await seedStatus(makeStatus({ version: 'v0.1.0', start_time: 111 }));

        mockBeginUpdate.mockRejectedValue(new Error('network'));

        await getUpdate();

        expect(mockAddNoticeToast).toHaveBeenCalled();
        expect(dashboardState.processingUpdate).toBe(false);
        expect(mockReload).not.toHaveBeenCalled();
    });
});

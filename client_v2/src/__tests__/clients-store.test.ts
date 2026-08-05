import { describe, it, expect, vi, beforeEach } from 'vitest';

const mocks = vi.hoisted(() => ({
    clientsCacheClear: vi.fn(),
    addSuccessToast: vi.fn(),
    addErrorToast: vi.fn(),
}));

vi.mock('panel/api/generated', () => ({
    clientsCacheClear: mocks.clientsCacheClear,
    clientsAdd: vi.fn(),
    clientsDelete: vi.fn(),
    clientsUpdate: vi.fn(),
}));

vi.mock('panel/stores/toasts', () => ({
    addSuccessToast: mocks.addSuccessToast,
    addErrorToast: mocks.addErrorToast,
}));

vi.mock('panel/stores/dashboard', () => ({
    getClients: vi.fn(),
}));

vi.mock('panel/common/intl', () => ({
    default: { getMessage: vi.fn((key: string) => key) },
}));

import { clearClientCache } from 'panel/stores/clients';

describe('clearClientCache', () => {
    beforeEach(() => vi.clearAllMocks());

    it('calls clientsCacheClear with the client name and shows a success toast', async () => {
        mocks.clientsCacheClear.mockResolvedValue(undefined);

        await clearClientCache('My Phone');

        expect(mocks.clientsCacheClear).toHaveBeenCalledTimes(1);
        expect(mocks.clientsCacheClear).toHaveBeenCalledWith({ name: 'My Phone' });
        expect(mocks.addSuccessToast).toHaveBeenCalledTimes(1);
        expect(mocks.addErrorToast).not.toHaveBeenCalled();
    });

    it('shows an error toast when the API call fails', async () => {
        mocks.clientsCacheClear.mockRejectedValue(new Error('boom'));

        await clearClientCache('My Phone');

        expect(mocks.addErrorToast).toHaveBeenCalledTimes(1);
        expect(mocks.addErrorToast).toHaveBeenCalledWith({ error: expect.any(Error) });
        expect(mocks.addSuccessToast).not.toHaveBeenCalled();
    });
});

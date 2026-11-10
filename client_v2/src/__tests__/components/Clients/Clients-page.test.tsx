import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render } from '@solidjs/testing-library';

const mocks = vi.hoisted(() => ({
    dashboardState: {
        clients: [] as unknown[],
        autoClients: [] as unknown[],
        clientsInitialized: true,
    },
    statsState: {
        normalizedTopClients: {} as Record<string, number>,
        statsInitialized: true,
    },
    clientsState: { processingDeleting: false },
    servicesState: { allServices: [] as unknown[] },
}));

vi.mock('panel/stores/dashboard', () => ({
    dashboardState: mocks.dashboardState,
    getClients: vi.fn(),
}));
vi.mock('panel/stores/stats', () => ({
    statsState: mocks.statsState,
    getStats: vi.fn(),
}));
vi.mock('panel/stores/clients', () => ({
    clientsState: mocks.clientsState,
    deleteClient: vi.fn(),
}));
vi.mock('panel/stores/services', () => ({
    servicesState: mocks.servicesState,
    getAllBlockedServices: vi.fn(),
}));
vi.mock('panel/stores/clientForm', () => ({
    initClientForm: vi.fn(),
    buildFormPayload: vi.fn(),
}));
vi.mock('@solidjs/router', () => ({
    useNavigate: () => vi.fn(),
    useSearchParams: () => [{}, vi.fn()],
}));
vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);

import { Clients } from 'panel/components/Clients/Clients';
import { getStats } from 'panel/stores/stats';

describe('Clients page', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('loads stats without searching client info', () => {
        render(() => <Clients />);

        expect(getStats).toHaveBeenCalledWith(undefined, 0);
    });
});

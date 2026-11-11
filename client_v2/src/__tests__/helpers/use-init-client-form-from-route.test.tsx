import { render, screen, waitFor } from '@solidjs/testing-library';
import { MemoryRouter, Route, createMemoryHistory } from '@solidjs/router';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const dashboardMocks = vi.hoisted(() => ({
    getClients: vi.fn(),
    dashboardState: {
        clients: [] as unknown[],
        clientsInitialized: true,
        supportedTags: [] as string[],
    },
}));

vi.mock('panel/stores/dashboard', async () => {
    const actual =
        await vi.importActual<typeof import('panel/stores/dashboard')>('panel/stores/dashboard');

    return {
        ...actual,
        getClients: dashboardMocks.getClients,
        get dashboardState() {
            return dashboardMocks.dashboardState;
        },
    };
});

import { useInitClientFormFromRoute } from 'panel/hooks/useInitClientFormFromRoute';
import {
    clearClientForm,
    clientFormState,
    initClientForm,
    setProcessingSave,
    updateClientFormField,
} from 'panel/stores/clientForm';

const Probe = () => {
    useInitClientFormFromRoute();

    return <div data-testid="probe" />;
};

const renderAt = (path: string) => {
    const history = createMemoryHistory();
    history.set({ value: path });

    render(() => (
        <MemoryRouter history={history}>
            <Route path="/clients/edit/:clientName" component={Probe} />
        </MemoryRouter>
    ));

    return { history };
};

const laptop = {
    name: 'Laptop',
    ids: ['192.168.1.1'],
    use_global_blocked_services: true,
    blocked_services: ['youtube'],
    blocked_services_schedule: {
        time_zone: 'UTC',
        mon: { start: 0, end: 60 },
    },
};

const desktop = {
    name: 'Desktop',
    ids: ['192.168.1.2'],
    use_global_blocked_services: false,
    blocked_services: [] as string[],
    blocked_services_schedule: {
        time_zone: 'UTC',
    },
};

describe('useInitClientFormFromRoute', () => {
    beforeEach(() => {
        clearClientForm();
        dashboardMocks.getClients.mockReset();
        dashboardMocks.dashboardState.clients = [laptop, desktop];
        dashboardMocks.dashboardState.clientsInitialized = true;
    });

    it('initializes the form from the client in the route', async () => {
        renderAt('/clients/edit/Laptop');

        await waitFor(() => {
            expect(clientFormState.mode).toBe('edit');
        });

        expect(clientFormState.name).toBe('Laptop');
        expect(clientFormState.use_global_blocked_services).toBe(true);
        expect(clientFormState.blocked_services).toEqual(['youtube']);
        expect(clientFormState.blocked_services_schedule.mon).toEqual({ start: 0, end: 60 });
    });

    it('keeps the form untouched when it already matches the route', async () => {
        initClientForm({ name: 'Laptop', use_global_blocked_services: false });
        updateClientFormField('blocked_services', ['steam']);
        renderAt('/clients/edit/Laptop');

        await waitFor(() => {
            expect(screen.getByTestId('probe')).toBeInTheDocument();
        });

        expect(clientFormState.name).toBe('Laptop');
        expect(clientFormState.blocked_services).toEqual(['steam']);
    });

    it('initializes the form without fetching when clients are already loaded', async () => {
        renderAt('/clients/edit/Laptop');

        await waitFor(() => {
            expect(clientFormState.mode).toBe('edit');
        });

        expect(clientFormState.name).toBe('Laptop');
        expect(dashboardMocks.getClients).not.toHaveBeenCalled();
    });

    it('fetches clients once when the edit URL loads directly', async () => {
        dashboardMocks.dashboardState.clients = [];
        dashboardMocks.dashboardState.clientsInitialized = false;
        // The plain-object mock is not reactive, so populate synchronously;
        // the real store re-runs the effect when its async fetch settles.
        dashboardMocks.getClients.mockImplementation(() => {
            dashboardMocks.dashboardState.clients = [laptop, desktop];
            dashboardMocks.dashboardState.clientsInitialized = true;
        });

        renderAt('/clients/edit/Laptop');

        await waitFor(() => {
            expect(clientFormState.mode).toBe('edit');
        });

        expect(dashboardMocks.getClients).toHaveBeenCalledTimes(1);
        expect(clientFormState.name).toBe('Laptop');
    });

    it('re-initializes when the route switches to another client', async () => {
        const { history } = renderAt('/clients/edit/Laptop');

        await waitFor(() => {
            expect(clientFormState.name).toBe('Laptop');
        });

        history.set({ value: '/clients/edit/Desktop' });

        await waitFor(() => {
            expect(clientFormState.name).toBe('Desktop');
        });
        expect(clientFormState.originalName).toBe('Desktop');
        expect(clientFormState.use_global_blocked_services).toBe(false);
    });

    it('does not re-initialize while a save is in flight', async () => {
        initClientForm({ name: 'Laptop', use_global_blocked_services: true });
        setProcessingSave(true);
        renderAt('/clients/edit/Desktop');

        await waitFor(() => {
            expect(screen.getByTestId('probe')).toBeInTheDocument();
        });

        expect(clientFormState.name).toBe('Laptop');
    });
});

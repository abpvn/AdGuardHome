import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@solidjs/testing-library';
import { MemoryRouter, Route, createMemoryHistory } from '@solidjs/router';

vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);
vi.mock('panel/stores/toasts', () => ({
    addSuccessToast: vi.fn(),
}));

import { PersistentClientsTable } from 'panel/components/Clients/blocks/PersistentClientsTable';
import type { Client } from 'panel/initialState';

const renderTable = (clients: Client[], topClients: Record<string, number>) => {
    const history = createMemoryHistory();
    history.set({ value: '/' });

    return render(() => (
        <MemoryRouter history={history}>
            <Route
                path="/"
                component={() => (
                    <PersistentClientsTable
                        clients={clients}
                        normalizedTopClients={topClients}
                        onEdit={vi.fn()}
                        onDelete={vi.fn()}
                        serviceMap={new Map()}
                    />
                )}
            />
        </MemoryRouter>
    ));
};

const client = (ids: string[]): Client => ({
    name: 'MyPhone',
    ids,
    use_global_settings: true,
    use_global_filters: true,
    use_global_blocked_services: true,
});

describe('PersistentClientsTable — request counts', () => {
    it('sums the counts of every identifier of the client', () => {
        renderTable([client(['10.0.0.5', '192.168.1.0/24', 'cli42'])], {
            '10.0.0.5': 3,
            '192.168.1.77': 2,
            cli42: 4,
        });

        expect(screen.getByText('9')).toBeInTheDocument();
    });

    it('sums multiple top-client entries of the same client instead of overwriting', () => {
        renderTable([client(['10.0.0.5', '10.0.0.6'])], {
            '10.0.0.5': 3,
            '10.0.0.6': 4,
        });

        expect(screen.getByText('7')).toBeInTheDocument();
    });

    it('shows zero when the client is not among the top clients', () => {
        renderTable([client(['10.0.0.5'])], {});

        expect(screen.getByText('0')).toBeInTheDocument();
    });
});

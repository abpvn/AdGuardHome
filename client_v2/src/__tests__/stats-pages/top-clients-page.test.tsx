import { render, screen } from '@solidjs/testing-library';
import { HashRouter, Route } from '@solidjs/router';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const mocks = vi.hoisted(() => ({
    statsState: {
        topClients: [] as { name: string; count: number; info?: unknown }[],
        numDnsQueries: 0,
        processingStats: false,
    },
    accessState: { disallowed_clients: '', processing: false },
}));

vi.mock('panel/stores/stats', () => ({
    statsState: mocks.statsState,
    getStats: vi.fn(),
    getStatsConfig: vi.fn(),
}));

vi.mock('panel/stores/access', () => ({
    accessState: mocks.accessState,
    getAccessList: vi.fn(),
}));

vi.mock('panel/stores/clientForm', () => ({
    initClientForm: vi.fn(),
}));

vi.mock('panel/components/Stats/hooks/useStatsRefresh', () => ({
    useStatsRefresh: vi.fn(() => vi.fn()),
}));

vi.mock('panel/common/ui/ClientBlockConfirm', () => ({
    ClientBlockConfirmDialog: (): null => null,
    useClientBlockConfirm: (): {
        confirmState: null;
        isClientBlocked: (client: string) => boolean;
        openConfirmDialog: () => void;
        closeConfirmDialog: () => void;
        handleConfirm: () => void;
    } => ({
        confirmState: null,
        isClientBlocked: () => false,
        openConfirmDialog: () => undefined,
        closeConfirmDialog: () => undefined,
        handleConfirm: () => undefined,
    }),
}));

import { TopClientsPage } from 'panel/components/Stats/TopClientsPage';

const mockMatchMedia = (matches: boolean) => {
    Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: (query: string) =>
            ({
                matches,
                media: query,
                onchange: null,
                addListener: () => {},
                removeListener: () => {},
                addEventListener: () => {},
                removeEventListener: () => {},
                dispatchEvent: () => false,
            }) as MediaQueryList,
    });
};

describe('TopClientsPage', () => {
    beforeEach(() => {
        mockMatchMedia(true);
        localStorage.clear();
        window.location.hash = '#/';
        mocks.statsState.topClients = [
            {
                name: '2001:db8:85a3::8a2e:370:7334',
                count: 2,
                info: { name: '', whois_info: {} },
            },
            { name: '10.0.0.1', count: 5, info: { name: '', whois_info: {} } },
        ];
        mocks.statsState.numDnsQueries = 10;
        mocks.statsState.processingStats = false;
        mocks.accessState.disallowed_clients = '';
    });

    const renderPage = () =>
        render(() => (
            <HashRouter>
                <Route path="/" component={TopClientsPage} />
            </HashRouter>
        ));

    it('gives the IP column a generous minimum width and caps the queries column', () => {
        renderPage();

        const row = document.querySelector('[class*="tableRow"]') as HTMLElement;
        expect(row).not.toBeNull();
        expect(row.style.getPropertyValue('--table-columns')).toBe(
            'minmax(0, 1fr) 93px minmax(90px, 140px) minmax(210px, 1fr) 219px 48px',
        );
    });

    it('renders a full IPv6 address inside the IP cell link', () => {
        renderPage();

        const fullIpv6 = '2001:db8:85a3::8a2e:370:7334';
        const cells = screen.getAllByTestId('client-ip-cell');
        expect(cells.map((cell) => cell.textContent)).toContain(fullIpv6);
    });
});
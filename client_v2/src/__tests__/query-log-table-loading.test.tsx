import { describe, expect, it, vi } from 'vitest';
import type { ComponentProps } from 'solid-js';
import { render, screen } from '@solidjs/testing-library';

import { LogTable } from 'panel/components/QueryLog/blocks/LogTable/LogTable';
import type { NormalizedQueryLogItem } from 'panel/helpers/helpers';

vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);

vi.mock('panel/common/ui/Table/Table', () => ({
    Table: () => <div data-testid="table-mock" />,
}));

vi.mock('panel/common/ui/Loader', () => ({
    Loader: () => <div data-testid="loader" />,
}));

vi.mock('panel/components/QueryLog/blocks/InfiniteScrollTrigger', () => ({
    InfiniteScrollTrigger: (): null => null,
}));

vi.mock('panel/components/QueryLog/blocks/EmptyState/EmptyState', () => ({
    EmptyState: (): null => null,
}));

vi.mock('panel/components/QueryLog/blocks/ActionsMenu', () => ({
    ActionsMenu: (): null => null,
}));

vi.mock('panel/components/QueryLog/blocks/LogTable/blocks', () => ({
    ClientCell: (): null => null,
    RequestCell: (): null => null,
    ReasonCell: (): null => null,
    StatusCell: (): null => null,
    TimeCell: (): null => null,
}));

const makeEntry = (overrides: Partial<NormalizedQueryLogItem> = {}): NormalizedQueryLogItem => ({
    time: '2026-08-25T10:00:00Z',
    domain: 'example.org',
    unicodeName: 'example.org',
    type: 'A',
    response: [],
    client: '192.168.0.40',
    client_info: null,
    rules: [],
    originalResponse: [],
    tracker: null,
    ...overrides,
});

const defaultProps: ComponentProps<typeof LogTable> = {
    logs: [makeEntry()],
    emptyStateMode: 'disabled' as const,
    hasMore: false,
    isLoadingMore: false,
    isRequestInFlight: false,
    isInitialLoading: false,
    isFilterReloading: false,
    infiniteScrollResetToken: '',
    onLoadMore: vi.fn(),
    onRowClick: vi.fn(),
    onBlock: vi.fn(),
    onUnblock: vi.fn(),
    onBlockClient: vi.fn(),
    onDisallowClient: vi.fn(),
    onAddPersistentClient: vi.fn(),
    onSearchSelect: vi.fn(),
    filters: [],
    services: [],
    whitelistFilters: [],
    clientsFilters: [],
    persistentClientIds: [],
    persistentClientsLoaded: true,
};

const renderLogTable = (overrides: Record<string, unknown> = {}) =>
    render(() => <LogTable {...defaultProps} {...overrides} />);

describe('QueryLog LogTable reload overlay', () => {
    it('shows the reload overlay while a filter reload is in flight', () => {
        renderLogTable({ isFilterReloading: true });

        expect(screen.getByTestId('query-log-table-loading-overlay')).toBeInTheDocument();
    });

    it('hides the reload overlay when not reloading', () => {
        renderLogTable({ isFilterReloading: false });

        expect(screen.queryByTestId('query-log-table-loading-overlay')).not.toBeInTheDocument();
    });
});
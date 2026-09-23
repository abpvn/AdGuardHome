import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@solidjs/testing-library';

import { Header } from 'panel/components/QueryLog/blocks/Header/Header';
import { copyInDom } from './helpers/copy';

vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);

vi.mock('panel/lib/theme', () => {
    const make = (names: string[]) => Object.fromEntries(names.map((name) => [name, name]));
    return {
        default: {
            layout: make(['title']),
            title: make(['h4', 'h3_tablet']),
        },
    };
});

vi.mock('panel/hooks/useIsMobile', () => ({
    useIsMobile: () => () => false,
}));

vi.mock('panel/stores/dashboard', () => ({
    dashboardState: { clients: [] },
}));

vi.mock('panel/common/controls/Input', () => ({
    Input: (props: any) => (
        <div>
            {props.prefixIcon}
            <input
                data-testid={props['data-testid']}
                placeholder={props.placeholder}
                value={props.value}
                onInput={(event) => props.onInput(event)}
            />
            {props.suffixIcon}
        </div>
    ),
}));

vi.mock('panel/common/controls/Select', () => ({
    Select: (): null => null,
}));

vi.mock('panel/common/ui/Button', () => ({
    Button: (props: any) => (
        <button
            type="button"
            data-testid={props['data-testid']}
            aria-label={props['aria-label']}
            title={props.title}
            disabled={props.disabled}
            onClick={(event) => props.onClick(event)}
        >
            {props.children}
        </button>
    ),
}));

vi.mock('panel/common/ui/Icon', () => ({
    Icon: (props: any) => <span data-testid={`icon-${props.icon}`} />,
}));

vi.mock('panel/common/ui/Loader', () => ({
    InlineLoader: () => <span data-testid="inline-loader" />,
}));

vi.mock('panel/common/ui/FaqTooltip', () => ({
    FaqTooltip: (props: any) => <span data-testid="faq-tooltip">{props.text}</span>,
}));

const defaultProps = {
    onSearch: vi.fn(),
    onRefresh: vi.fn(),
    onStatusFilterChange: vi.fn(),
    onReasonFilterChange: vi.fn(),
    onClientFilterChange: vi.fn(),
    currentSearch: '',
    currentStatus: 'all',
    currentReason: 'all',
    currentClient: '',
    isLoading: false,
};

const renderHeader = (overrides: Record<string, unknown> = {}) =>
    render(() => <Header {...defaultProps} {...overrides} />);

describe('QueryLog Header search loading state', () => {
    it('keeps the clear button visible while loading when there is text', () => {
        renderHeader({ currentSearch: 'example.org', isLoading: true });

        expect(screen.getByTestId('query-log-search-clear-button')).toBeInTheDocument();
        expect(screen.getByTestId('inline-loader')).toBeInTheDocument();
    });

    it('shows only the loader while loading with an empty search', () => {
        renderHeader({ currentSearch: '', isLoading: true });

        expect(screen.queryByTestId('query-log-search-clear-button')).not.toBeInTheDocument();
        expect(screen.getByTestId('inline-loader')).toBeInTheDocument();
    });

    it('hides the loader and shows only the clear button when idle', () => {
        renderHeader({ currentSearch: 'example.org', isLoading: false });

        expect(screen.queryByTestId('inline-loader')).not.toBeInTheDocument();
        expect(screen.getByTestId('query-log-search-clear-button')).toBeInTheDocument();
    });

    it('reveals the clear button as soon as the user types', () => {
        renderHeader({ currentSearch: '', isLoading: false });

        expect(screen.queryByTestId('query-log-search-clear-button')).not.toBeInTheDocument();

        fireEvent.input(screen.getByTestId('query-log-search-input'), {
            target: { value: 'example.org' },
        });

        expect(screen.getByTestId('query-log-search-clear-button')).toBeInTheDocument();
    });

    it('renders the strict-search tooltip copy', () => {
        renderHeader({});

        expect(screen.getByTestId('faq-tooltip')).toHaveTextContent(
            copyInDom('query_log_strict_search'),
        );
    });
});
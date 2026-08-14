import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@solidjs/testing-library';

import { THEMES } from 'panel/helpers/constants';

type ChangeListener = () => void;

const changeListeners = new Set<ChangeListener>();

vi.stubGlobal(
    'matchMedia',
    vi.fn().mockImplementation((query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: (_: string, handler: ChangeListener) => changeListeners.add(handler),
        removeEventListener: (_: string, handler: ChangeListener) => changeListeners.delete(handler),
        dispatchEvent: () => false,
    })),
);

vi.mock('panel/stores/dashboard', () => ({
    dashboardState: {
        processing: false,
        isCoreRunning: true,
        language: 'en',
        theme: THEMES.auto,
        protectionEnabled: false,
    },
    getDnsStatus: vi.fn(),
    getTimerStatus: vi.fn(),
}));

vi.mock('panel/common/ui/Header', () => ({
    Header: () => <div data-testid="chrome-header" />,
}));
vi.mock('panel/common/ui/Banners', () => ({
    Banners: () => <div data-testid="chrome-banners" />,
}));
vi.mock('panel/common/ui/Sidebar', () => ({
    Sidebar: () => <div data-testid="chrome-sidebar" />,
}));
vi.mock('panel/common/ui/Footer', () => ({
    Footer: () => <div data-testid="chrome-footer" />,
}));
vi.mock('panel/common/ui/Icons', () => ({ Icons: (): null => null }));
vi.mock('panel/components/Toasts', () => ({ Toasts: (): null => null }));
vi.mock('panel/components/Dashboard', () => ({
    Dashboard: () => <div data-testid="route-dashboard" />,
}));

import App from '../components/App';

describe('App theme effect', () => {
    beforeEach(() => {
        changeListeners.clear();
        window.location.hash = '#/dashboard';
    });

    it('subscribes to the OS color scheme when the theme is "auto"', async () => {
        render(() => <App />);

        await screen.findByTestId('route-dashboard');

        expect(changeListeners.size).toBe(1);
    });

    it('keeps the "auto" preference when the OS color scheme changes', async () => {
        render(() => <App />);

        await screen.findByTestId('route-dashboard');

        // Simulate the OS switching to light: the handler re-resolves "auto".
        document.documentElement.dataset.theme = THEMES.dark;
        changeListeners.forEach((listener) => listener());

        expect(document.documentElement.dataset.theme).toBe(THEMES.light);
        expect(localStorage.getItem('account_theme')).toBe(JSON.stringify(THEMES.auto));
    });

    it('removes the OS color scheme listener on unmount', async () => {
        const { unmount } = render(() => <App />);

        await screen.findByTestId('route-dashboard');
        expect(changeListeners.size).toBe(1);

        unmount();

        expect(changeListeners.size).toBe(0);
    });
});

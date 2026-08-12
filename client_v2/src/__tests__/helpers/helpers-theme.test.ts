import { describe, it, expect, beforeEach, vi } from 'vitest';

import { resolveTheme, setUITheme, getTheme } from 'panel/helpers/helpers';
import { LocalStorageHelper, LOCAL_STORAGE_KEYS } from 'panel/helpers/localStorageHelper';
import { THEMES } from 'panel/helpers/constants';

const setMatchMediaDark = (matches: boolean) => {
    vi.stubGlobal(
        'matchMedia',
        vi.fn().mockImplementation((query: string) => ({
            matches,
            media: query,
            onchange: null,
            addListener: () => {},
            removeListener: () => {},
            addEventListener: () => {},
            removeEventListener: () => {},
            dispatchEvent: () => false,
        })),
    );
};

describe('theme helpers', () => {
    beforeEach(() => {
        localStorage.clear();
        vi.unstubAllGlobals();
        setMatchMediaDark(false);
    });

    describe('resolveTheme', () => {
        it('returns the theme unchanged when it is explicit', () => {
            expect(resolveTheme(THEMES.dark)).toBe(THEMES.dark);
            expect(resolveTheme(THEMES.light)).toBe(THEMES.light);
        });

        it('resolves "auto" to "dark" when the OS prefers dark', () => {
            setMatchMediaDark(true);

            expect(resolveTheme(THEMES.auto)).toBe(THEMES.dark);
        });

        it('resolves "auto" to "light" when the OS prefers light', () => {
            setMatchMediaDark(false);

            expect(resolveTheme(THEMES.auto)).toBe(THEMES.light);
        });
    });

    describe('setUITheme', () => {
        it('stores the raw preference and applies the resolved theme to the document', () => {
            setMatchMediaDark(true);

            setUITheme(THEMES.auto);

            expect(LocalStorageHelper.getItem(LOCAL_STORAGE_KEYS.THEME)).toBe(THEMES.auto);
            expect(document.documentElement.dataset.theme).toBe(THEMES.dark);
            expect(document.documentElement.style.colorScheme).toBe(THEMES.dark);
        });

        it('keeps the "auto" preference while applying the current OS theme', () => {
            setMatchMediaDark(true);
            setUITheme(THEMES.auto);
            setMatchMediaDark(false);
            setUITheme(THEMES.auto);

            expect(LocalStorageHelper.getItem(LOCAL_STORAGE_KEYS.THEME)).toBe(THEMES.auto);
            expect(document.documentElement.dataset.theme).toBe(THEMES.light);
        });

        it('stores and applies an explicit theme', () => {
            setUITheme(THEMES.dark);

            expect(LocalStorageHelper.getItem(LOCAL_STORAGE_KEYS.THEME)).toBe(THEMES.dark);
            expect(document.documentElement.dataset.theme).toBe(THEMES.dark);
            expect(document.documentElement.style.colorScheme).toBe(THEMES.dark);
        });

        it('resolves the stored "auto" preference when no theme argument is passed', () => {
            setMatchMediaDark(true);
            LocalStorageHelper.setItem(LOCAL_STORAGE_KEYS.THEME, THEMES.auto);

            setUITheme();

            expect(getTheme()).toBe(THEMES.auto);
            expect(document.documentElement.dataset.theme).toBe(THEMES.dark);
        });
    });
});

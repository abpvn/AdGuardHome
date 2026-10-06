import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@solidjs/testing-library';

const mocks = vi.hoisted(() => ({
    accessState: {
        processingSet: false,
        allowed_countries: 'VN',
        blocked_countries: 'GB',
    },
    setAccessList: vi.fn(),
}));

vi.mock('panel/stores/access', () => ({
    get accessState() {
        return mocks.accessState;
    },
    setAccessList: mocks.setAccessList,
}));

import { AllowedCountriesDialog } from 'panel/components/DnsSettings/Access/blocks/AllowedCountriesDialog';
import { BlockedCountriesDialog } from 'panel/components/DnsSettings/Access/blocks/BlockedCountriesDialog';
import { DB_IP_LINK } from 'panel/helpers/constants';

const link = () => screen.getByRole('link');

// The real `intl` is used on purpose: the copy helper flattens a message to a
// string, so only the real translator turns the `<a>` in the message into a
// rendered anchor.
describe('country access dialogs', () => {
    // REGRESSION: the country descriptions point at the GeoIP database, so a
    // bare URL leaves the user without the source of the country codes and
    // without a way to open it.
    it('links the GeoIP database in a new tab for the allowed list', () => {
        render(() => (
            <AllowedCountriesDialog open={() => true} onClose={() => {}} processing={false} />
        ));

        expect(link()).toHaveAttribute('href', DB_IP_LINK);
        expect(link()).toHaveAttribute('target', '_blank');
        expect(link()).toHaveAttribute('rel', 'noopener noreferrer');
    });

    it('links the GeoIP database in a new tab for the blocked list', () => {
        render(() => (
            <BlockedCountriesDialog open={() => true} onClose={() => {}} processing={false} />
        ));

        expect(link()).toHaveAttribute('href', DB_IP_LINK);
        expect(link()).toHaveAttribute('target', '_blank');
    });
});
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@solidjs/testing-library';
import userEvent from '@testing-library/user-event';

const mocks = vi.hoisted(() => ({
    setTlsConfig: vi.fn(),
    encryptionState: {
        insecure_enabled: false,
        processingConfig: false,
    },
}));

vi.mock('panel/stores/encryption', () => ({
    encryptionState: mocks.encryptionState,
    setTlsConfig: mocks.setTlsConfig,
}));
vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);

import { InsecureToggle } from 'panel/components/Encryption/blocks/InsecureToggle';
import { copyInDom } from 'panel/__tests__/helpers/copy';

const switchInput = () => screen.getByRole('checkbox');

beforeEach(() => {
    vi.clearAllMocks();
    mocks.encryptionState.insecure_enabled = false;
    mocks.encryptionState.processingConfig = false;
    mocks.setTlsConfig.mockResolvedValue({ ok: true });
});

describe('InsecureToggle', () => {
    it('shows the stored value and saves the switched one', async () => {
        const user = userEvent.setup();
        render(() => <InsecureToggle />);

        expect(switchInput()).not.toBeChecked();
        expect(screen.getByText(copyInDom('encryption_insecure_enabled_enable'))).toBeInTheDocument();

        await user.click(switchInput());

        expect(mocks.setTlsConfig).toHaveBeenCalledWith({ insecure_enabled: true });
    });

    it('turns insecure DNS off again', async () => {
        const user = userEvent.setup();
        mocks.encryptionState.insecure_enabled = true;
        render(() => <InsecureToggle />);

        expect(switchInput()).toBeChecked();

        await user.click(switchInput());

        expect(mocks.setTlsConfig).toHaveBeenCalledWith({ insecure_enabled: false });
    });

    it('keeps the shown value while the save is in flight, then follows the store', async () => {
        const user = userEvent.setup();
        render(() => <InsecureToggle />);

        mocks.encryptionState.processingConfig = true;
        await user.click(switchInput());

        // The switch flips on the click, so the pending save must not snap it
        // back to the store's old value mid-flight.
        await waitFor(() => {
            expect(switchInput()).toBeChecked();
        });

        mocks.encryptionState.processingConfig = false;
        await waitFor(() => {
            expect(switchInput()).toBeChecked();
        });
    });

    it('is disabled while a save is running', () => {
        mocks.encryptionState.processingConfig = true;
        render(() => <InsecureToggle />);

        expect(switchInput()).toBeDisabled();
    });
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@solidjs/testing-library';

import { copyInDom } from 'panel/__tests__/helpers/copy';

const mockEncryptionState: Record<string, any> = {
    enabled: true,
    certificate_path: '/etc/ssl/cert.pem',
    private_key_path: '/etc/ssl/key.pem',
    private_key_saved: false,
};

vi.mock('panel/stores/encryption', () => ({
    get encryptionState() {
        return mockEncryptionState;
    },
    setTlsConfig: vi.fn(),
    resetValidationStatus: vi.fn(),
}));

vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);

import { AddTlsCertModal } from 'panel/components/Encryption/blocks/AddTlsCert';

describe('AddTlsCertModal edit mode', () => {
    beforeEach(() => {
        Object.assign(mockEncryptionState, {
            enabled: true,
            certificate_path: '/etc/ssl/cert.pem',
            private_key_path: '/etc/ssl/key.pem',
            private_key_saved: false,
        });
    });

    it('shows edit titles when edit prop is true', () => {
        render(() => <AddTlsCertModal open={true} edit onClose={vi.fn()} />);

        expect(screen.getByText(copyInDom('edit_tls_certificate'))).toBeInTheDocument();
    });

    it('pre-fills the certificate path when editing a path-based cert', () => {
        render(() => <AddTlsCertModal open={true} edit onClose={vi.fn()} />);

        const pathInput = screen.getByLabelText(
            copyInDom('tls_cert_path_label'),
        ) as HTMLInputElement;
        expect(pathInput.value).toBe('/etc/ssl/cert.pem');
    });

    it('pre-fills the key path and shows the Save button on the key step', async () => {
        const user = (await import('@testing-library/user-event')).default;
        render(() => <AddTlsCertModal open={true} edit onClose={vi.fn()} />);

        await user.click(screen.getByText(copyInDom('next')));

        expect(
            screen.getByText(copyInDom('edit_tls_certificate_private_key')),
        ).toBeInTheDocument();
        const keyPath = screen.getByLabelText(
            copyInDom('tls_key_path_label'),
        ) as HTMLInputElement;
        expect(keyPath.value).toBe('/etc/ssl/key.pem');
        expect(screen.getByText(copyInDom('save'))).toBeInTheDocument();
    });
});
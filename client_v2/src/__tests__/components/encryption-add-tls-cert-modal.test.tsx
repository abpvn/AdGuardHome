import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@solidjs/testing-library';

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

vi.mock('panel/common/intl', () => {
    const intl = {
        getMessage: (key: string, _values?: any) => {
            const messages: Record<string, string> = {
                add_tls_certificate: 'Add TLS certificate',
                add_tls_certificate_private_key: 'Add TLS certificate private key',
                edit_tls_certificate: 'Edit TLS certificate',
                edit_tls_certificate_private_key: 'Edit TLS certificate private key',
                tls_cert_modal_description: 'description',
                next: 'Next',
                back: 'Back',
                add: 'Add',
                save: 'Save',
                tls_cert_path_option: 'Path',
                tls_key_path_option: 'Path',
                encryption_certificates_source_content: 'Content',
                encryption_key_source_content: 'Content',
                use_saved_key: 'Use saved key',
                path_to_file_placeholder: 'Path to file: local or Internet address',
                encryption_certificates_input: 'Paste your certificate chain here',
                encryption_key_input: 'Paste your private key here',
                tls_cert_path_label: 'Full path to the certificate file',
                tls_key_path_label: 'Full path to the private key file',
            };
            return messages[key] || key;
        },
        getUILanguage: () => 'en',
        changeLanguage: vi.fn(),
    };
    return { default: intl };
});

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

        expect(screen.getByText('Edit TLS certificate')).toBeInTheDocument();
    });

    it('pre-fills the certificate path when editing a path-based cert', () => {
        render(() => <AddTlsCertModal open={true} edit onClose={vi.fn()} />);

        const pathInput = screen.getByLabelText(
            'Full path to the certificate file',
        ) as HTMLInputElement;
        expect(pathInput.value).toBe('/etc/ssl/cert.pem');
    });

    it('pre-fills the key path and shows the Save button on the key step', async () => {
        const user = (await import('@testing-library/user-event')).default;
        render(() => <AddTlsCertModal open={true} edit onClose={vi.fn()} />);

        await user.click(screen.getByText('Next'));

        expect(screen.getByText('Edit TLS certificate private key')).toBeInTheDocument();
        const keyPath = screen.getByLabelText('Full path to the private key file') as HTMLInputElement;
        expect(keyPath.value).toBe('/etc/ssl/key.pem');
        expect(screen.getByText('Save')).toBeInTheDocument();
    });
});

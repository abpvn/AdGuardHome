import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@solidjs/testing-library';

const mockEncryptionState: Record<string, any> = {
    valid_chain: true,
    valid_cert: true,
    valid_key: true,
    valid_pair: true,
    subject: 'CN=example.com',
    issuer: 'CN=Let\'s Encrypt',
    not_after: '2027-01-01T00:00:00Z',
    dns_names: ['example.com'],
    key_type: 'RSA',
    warning_validation: '',
    certificate_chain: 'cert',
    private_key: 'key',
};

vi.mock('panel/stores/encryption', () => ({
    get encryptionState() {
        return mockEncryptionState;
    },
    setTlsConfig: vi.fn(),
    resetValidationStatus: vi.fn(),
    clearCertOptimistically: vi.fn(),
}));

vi.mock('panel/common/intl', () => {
    const intl = {
        getMessage: (key: string, values?: any) => {
            const messages: Record<string, string> = {
                tls_certificate: 'TLS certificate',
                delete_tls_certificate: 'Delete TLS certificate',
                delete_tls_certificate_desc: 'Delete the TLS certificate?',
                delete_table_action_confirm: 'Delete',
                cancel: 'Cancel',
                encryption_certificates: 'Certificates',
                encryption_key_cert_mismatch: 'Key and certificate do not match',
                encryption_certificate_has_issues: 'Certificate has issues',
                encryption_chain_valid: 'Certificate chain is valid',
                encryption_chain_invalid: 'Certificate chain is invalid',
                encryption_key_valid: 'Private key is valid',
                encryption_key_invalid: 'Private key is invalid',
                encryption_subject: `Subject: ${values?.value}`,
                encryption_issuer: `Issuer: ${values?.value}`,
                encryption_expire: `Expires: ${values?.value}`,
                encryption_hostnames: `Hostnames: ${values?.value}`,
                encryption_key_type: `Encryption algorithm: ${values?.value}`,
            };
            return messages[key] || key;
        },
        getUILanguage: () => 'en',
        changeLanguage: vi.fn(),
    };
    return { default: intl };
});

import { TlsCertSection } from 'panel/components/Encryption/blocks/TlsCertSection';

const renderSection = () => render(() => <TlsCertSection />);

describe('TlsCertSection', () => {
    beforeEach(() => {
        Object.assign(mockEncryptionState, {
            valid_chain: true,
            valid_cert: true,
            valid_key: true,
            valid_pair: true,
            subject: 'CN=example.com',
            issuer: 'CN=Let\'s Encrypt',
            not_after: '2027-01-01T00:00:00Z',
            dns_names: ['example.com'],
            key_type: 'RSA',
            warning_validation: '',
            certificate_chain: 'cert',
            private_key: 'key',
        });
    });

    it('renders certificate details when certificate is configured', () => {
        renderSection();

        expect(screen.getByText('Certificate chain is valid')).toBeInTheDocument();
        expect(screen.getByText('Subject: CN=example.com')).toBeInTheDocument();
        expect(screen.getByText(/Issuer: /)).toBeInTheDocument();
        expect(screen.getByText(/Expires: /)).toBeInTheDocument();
        expect(screen.getByText('Hostnames: example.com')).toBeInTheDocument();
        expect(screen.getByText('Private key is valid')).toBeInTheDocument();
        expect(screen.getByText('Encryption algorithm: RSA')).toBeInTheDocument();
    });

    it('shows warning message and certificate details together when a warning is present', () => {
        mockEncryptionState.warning_validation = 'Certificate will expire soon';

        renderSection();

        expect(screen.getByText('Certificate has issues')).toBeInTheDocument();
        expect(screen.getByText('Certificate will expire soon')).toBeInTheDocument();
        expect(screen.getByText('Certificate chain is valid')).toBeInTheDocument();
        expect(screen.getByText('Subject: CN=example.com')).toBeInTheDocument();
    });

    it('shows mismatch error and certificate details together', () => {
        mockEncryptionState.valid_pair = false;

        renderSection();

        expect(screen.getByText('Key and certificate do not match')).toBeInTheDocument();
        expect(screen.getByText('Certificate chain is valid')).toBeInTheDocument();
        expect(screen.getByText('Subject: CN=example.com')).toBeInTheDocument();
    });

    it('renders nothing when no certificate is configured', () => {
        mockEncryptionState.certificate_chain = '';
        mockEncryptionState.certificate_path = '';

        renderSection();

        expect(screen.queryByText('Certificate chain is valid')).not.toBeInTheDocument();
    });
});

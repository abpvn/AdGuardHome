import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@solidjs/testing-library';
import userEvent from '@testing-library/user-event';

import { copy, copyInDom } from 'panel/__tests__/helpers/copy';

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
    applyTlsOptimistically: vi.fn(),
}));

vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);

import { TlsCertSection } from 'panel/components/Encryption/blocks/TlsCertSection';

const renderSection = (props?: { onEdit?: () => void }) =>
    render(() => <TlsCertSection {...props} />);

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

        expect(screen.getByText(copyInDom('encryption_chain_valid'))).toBeInTheDocument();
        expect(
            screen.getByText(copyInDom('encryption_subject', { value: 'CN=example.com' })),
        ).toBeInTheDocument();
        expect(screen.getByText(new RegExp(copy('encryption_issuer').slice(0, 6)))).toBeInTheDocument();
        expect(screen.getByText(new RegExp(copy('encryption_expire').slice(0, 7)))).toBeInTheDocument();
        expect(
            screen.getByText(copyInDom('encryption_hostnames', { value: 'example.com' })),
        ).toBeInTheDocument();
        expect(screen.getByText(copyInDom('encryption_key_valid'))).toBeInTheDocument();
        expect(
            screen.getByText(copyInDom('encryption_key_type', { value: 'RSA' })),
        ).toBeInTheDocument();
    });

    it('shows warning message and certificate details together when a warning is present', () => {
        mockEncryptionState.warning_validation = 'Certificate will expire soon';

        renderSection();

        expect(
            screen.getByText(copyInDom('encryption_certificate_has_issues')),
        ).toBeInTheDocument();
        expect(screen.getByText('Certificate will expire soon')).toBeInTheDocument();
        expect(screen.getByText(copyInDom('encryption_chain_valid'))).toBeInTheDocument();
        expect(
            screen.getByText(copyInDom('encryption_subject', { value: 'CN=example.com' })),
        ).toBeInTheDocument();
    });

    it('shows mismatch error and certificate details together', () => {
        mockEncryptionState.valid_pair = false;

        renderSection();

        expect(
            screen.getByText(copyInDom('encryption_key_cert_mismatch')),
        ).toBeInTheDocument();
        expect(screen.getByText(copyInDom('encryption_chain_valid'))).toBeInTheDocument();
        expect(
            screen.getByText(copyInDom('encryption_subject', { value: 'CN=example.com' })),
        ).toBeInTheDocument();
    });

    it('renders nothing when no certificate is configured', () => {
        mockEncryptionState.certificate_chain = '';
        mockEncryptionState.certificate_path = '';

        renderSection();

        expect(screen.queryByText(copyInDom('encryption_chain_valid'))).not.toBeInTheDocument();
    });

    it('fires onEdit when the edit button is clicked', async () => {
        const onEdit = vi.fn();

        renderSection({ onEdit });

        await userEvent.click(screen.getByLabelText(copyInDom('edit_tls_certificate')));

        expect(onEdit).toHaveBeenCalledTimes(1);
    });
});
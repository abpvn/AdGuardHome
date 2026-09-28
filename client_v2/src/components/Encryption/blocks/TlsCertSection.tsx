import { createSignal, Show } from 'solid-js';

import { ConfirmDialog } from 'panel/common/ui/ConfirmDialog';
import { Icon } from 'panel/common/ui/Icon';
import intl from 'panel/common/intl';
import {
    applyTlsOptimistically,
    encryptionState,
    resetValidationStatus,
    setTlsConfig,
} from 'panel/stores/encryption';
import { dashboardState } from 'panel/stores/dashboard';
import { STANDARD_WEB_PORT } from 'panel/helpers/constants';
import { CertificateStatus, KeyStatus, ValidationStatus } from '../Status';
import { defaultTlsValues, getSubmitValues } from './helpers';
import s from '../styles.module.pcss';
import theme from 'panel/lib/theme';

export const TlsCertSection = (props: { onEdit?: () => void }) => {
    const [showDeleteConfirm, setShowDeleteConfirm] = createSignal(false);

    const enc = () => encryptionState;

    const handleRemoveCert = () => {
        // The removal has to clear the whole form, not just the PEM fields:
        // the wizard's `getSubmitValues` also drops the saved key and the
        // server names, so the section and the store cannot disagree about
        // what a removed certificate leaves behind.
        const values = getSubmitValues(defaultTlsValues);

        applyTlsOptimistically(values);
        resetValidationStatus();
        setTlsConfig(values);
        setShowDeleteConfirm(false);
    };

    const renderStatus = () => {
        const certInfo = () => {
            if (!enc().certificate_chain && !enc().certificate_path) return null;

            return (
                <>
                    <CertificateStatus
                        validChain={enc().valid_chain}
                        validCert={enc().valid_cert}
                        subject={enc().subject}
                        issuer={enc().issuer}
                        notAfter={enc().not_after}
                        dnsNames={enc().dns_names}
                    />
                    <Show when={enc().private_key || enc().private_key_path}>
                        <KeyStatus validKey={enc().valid_key} keyType={enc().key_type} />
                    </Show>
                </>
            );
        };

        // The message says what is wrong; the details below it say which
        // certificate is installed, which is what the user needs to act on it —
        // so the two stack instead of replacing each other.
        if (enc().valid_cert && enc().valid_key && !enc().valid_pair) {
            return (
                <>
                    <ValidationStatus
                        type="error"
                        message={intl.getMessage('encryption_key_cert_mismatch')}
                    />
                    {certInfo()}
                </>
            );
        }
        if (enc().warning_validation) {
            const isWarning = enc().valid_key && enc().valid_cert && enc().valid_pair;
            return (
                <>
                    <ValidationStatus
                        type={isWarning ? 'warning' : 'error'}
                        message={enc().warning_validation}
                    />
                    {certInfo()}
                </>
            );
        }
        return certInfo();
    };

    return (
        <div class={s.certSection} data-testid="tls-cert-section">
            <div class={s.certRow}>
                <span class={s.certTitle}>{intl.getMessage('tls_certificate')}</span>
                <div class={s.certActions}>
                    <Show when={props.onEdit}>
                        <button
                            type="button"
                            class={theme.form.action}
                            onClick={() => props.onEdit?.()}
                            aria-label={intl.getMessage('edit_tls_certificate')}
                        >
                            <Icon icon="edit" />
                        </button>
                    </Show>
                    <button
                        type="button"
                        class={theme.form.action}
                        onClick={() => setShowDeleteConfirm(true)}
                        aria-label={intl.getMessage('encryption_certificates')}
                        data-testid="tls-cert-remove"
                    >
                        <Icon icon="delete" color="red" />
                    </button>
                </div>
            </div>
            {renderStatus()}

            <Show when={showDeleteConfirm()}>
                <ConfirmDialog
                    title={intl.getMessage('remove_tls_certificate')}
                    // Removing the certificate stops the admin panel from being
                    // served over HTTPS, so the address that stops working is
                    // named here rather than left for the user to work out.
                    text={intl.getMessage('remove_tls_certificate_desc', {
                        host: window.location.hostname,
                        port: Number(dashboardState.httpPort) || STANDARD_WEB_PORT,
                    })}
                    buttonText={intl.getMessage('yes_remove')}
                    cancelText={intl.getMessage('cancel')}
                    buttonVariant="danger"
                    onConfirm={handleRemoveCert}
                    onClose={() => setShowDeleteConfirm(false)}
                />
            </Show>
        </div>
    );
};

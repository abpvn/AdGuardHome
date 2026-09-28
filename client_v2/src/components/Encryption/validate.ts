import intl from 'panel/common/intl';
import { ENCRYPTION_SOURCE } from 'panel/helpers/constants';
import {
    validateServerName,
    validatePort,
    validateIsSafePort,
    validatePlainDns,
    validateInsecureEnabled,
    validateRequiredValue,
    validatePath,
} from 'panel/helpers/validators';

export type EncryptionFormValues = {
    enabled?: boolean;
    serve_plain_dns?: boolean;
    insecure_enabled?: boolean;
    server_names?: string[];
    force_https?: boolean;
    port_https?: number;
    port_dns_over_tls?: number;
    port_dns_over_quic?: number;
    certificate_chain?: string;
    private_key?: string;
    certificate_path?: string;
    private_key_path?: string;
    certificate_source?: string;
    key_source?: string;
    private_key_saved?: boolean;
};

const validateCertPath = (value?: string): string | undefined => {
    if (value && validatePath(value)) {
        return intl.getMessage('encryption_unable_read_cert');
    }
    return undefined;
};

const validateKeyPath = (value?: string): string | undefined => {
    if (value && validatePath(value)) {
        return intl.getMessage('encryption_unable_read_key');
    }
    return undefined;
};

/** Matches any PEM private-key header, e.g. `-----BEGIN RSA PRIVATE KEY-----`. */
const R_PEM_KEY_HEADER = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;

/** Matches a PEM certificate header. */
const R_PEM_CERT_HEADER = /-----BEGIN CERTIFICATE-----/;

/** Matches a complete PEM certificate block: header, body, and closing line. */
const R_PEM_CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----/;

/** Matches a complete PEM private-key block of any flavour. */
const R_PEM_KEY_BLOCK =
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*-----END [A-Z0-9 ]*PRIVATE KEY-----/;

/**
 * Validates the certificate field content.  Only the cases the backend cannot
 * express are handled here — content that is obviously a private key, and
 * content that is not a complete PEM block (no header, or missing the closing
 * line to a partial copy).  Real parsing is left to the backend so the user
 * gets its precise message.
 */
const validateCertContent = (value?: string): string | undefined => {
    const required = validateRequiredValue(value);
    if (required) return required;

    const text = String(value);
    if (R_PEM_KEY_HEADER.test(text)) return intl.getMessage('tls_setup_error_not_a_cert');
    if (!R_PEM_CERT_BLOCK.test(text)) return intl.getMessage('tls_setup_error_cert_incomplete');

    return undefined;
};

/** Validates the private-key field content, mirroring [validateCertContent]. */
const validateKeyContent = (value?: string): string | undefined => {
    const required = validateRequiredValue(value);
    if (required) return required;

    const text = String(value);
    if (R_PEM_CERT_HEADER.test(text) && !R_PEM_KEY_HEADER.test(text)) {
        return intl.getMessage('tls_setup_error_not_a_key');
    }
    if (!R_PEM_KEY_BLOCK.test(text)) return intl.getMessage('tls_setup_error_key_incomplete');

    return undefined;
};

/**
 * Validates only the certificate fields (chain or path).
 * Used by step 1 of the Add TLS Certificate modal.
 */
export const validateCertFields = (values: EncryptionFormValues): Record<string, string> => {
    const errs: Record<string, string> = {};

    if (values.certificate_source === ENCRYPTION_SOURCE.CONTENT) {
        const certErr = validateCertContent(values.certificate_chain);
        if (certErr) errs.certificate_chain = certErr;
    } else {
        const certPathErr =
            validateRequiredValue(values.certificate_path) ||
            validateCertPath(values.certificate_path);
        if (certPathErr) errs.certificate_path = certPathErr;
    }

    return errs;
};

/**
 * Validates only the private key fields (key or path).
 * Used by step 2 of the Add TLS Certificate modal.
 */
export const validateKeyFields = (values: EncryptionFormValues): Record<string, string> => {
    const errs: Record<string, string> = {};

    if (values.private_key_saved) return errs;

    if (values.key_source === ENCRYPTION_SOURCE.CONTENT) {
        const keyErr = validateKeyContent(values.private_key);
        if (keyErr) errs.private_key = keyErr;
    } else if (values.key_source === ENCRYPTION_SOURCE.PATH) {
        const keyPathErr =
            validateRequiredValue(values.private_key_path) ||
            validateKeyPath(values.private_key_path);
        if (keyPathErr) errs.private_key_path = keyPathErr;
    }

    return errs;
};

/**
 * Validates certificate and private key fields together.
 */
export const validateCertKeyFields = (values: EncryptionFormValues): Record<string, string> => {
    const errs: Record<string, string> = {};
    Object.assign(errs, validateCertFields(values), validateKeyFields(values));
    return errs;
};

/** Ports of the other AdGuard Home settings, used for conflict detection. */
export type ExternalPorts = {
    /** Web UI (HTTP/HTTPS) port. */
    webUi?: number;
    /** Plain DNS port. */
    plainDns?: number;
    /** DNSCrypt TCP port. */
    dnscrypt?: number;
};

/**
 * Mirrors the backend `validatePorts` (internal/home/web.go): ports may not
 * repeat within the TCP family {web UI, HTTPS, DoT, DNSCrypt, plain DNS} and
 * the UDP family {plain DNS, DoQ}.  Cross-family equality is allowed, zero
 * ports are skipped.
 *
 * Only the encrypted DNS ports (`port_*`) are flagged — the external settings
 * are read-only, so a conflict between them is left to the backend.
 */
export const validatePortConflicts = (
    values: EncryptionFormValues,
    externalPorts?: ExternalPorts,
): Record<string, string> => {
    const errs: Record<string, string> = {};
    const msg = intl.getMessage('tls_setup_error_port_in_use');

    const tcp: Record<string, number> = {
        port_https: Number(values.port_https) || 0,
        port_dns_over_tls: Number(values.port_dns_over_tls) || 0,
        webUi: externalPorts?.webUi || 0,
        plainDns: externalPorts?.plainDns || 0,
        dnscrypt: externalPorts?.dnscrypt || 0,
    };
    const udp: Record<string, number> = {
        port_dns_over_quic: Number(values.port_dns_over_quic) || 0,
        plainDns: externalPorts?.plainDns || 0,
    };

    for (const family of [tcp, udp]) {
        const byPort = new Map<number, string[]>();
        for (const [field, port] of Object.entries(family)) {
            if (!port) continue;
            byPort.set(port, [...(byPort.get(port) ?? []), field]);
        }
        for (const fields of byPort.values()) {
            if (fields.length < 2) continue;
            for (const field of fields.filter((f) => f.startsWith('port_'))) {
                errs[field] = msg;
            }
        }
    }

    return errs;
};

/** Port inputs of the encrypted DNS settings — the fields owned by both hosts. */
export type PortField = 'port_https' | 'port_dns_over_tls' | 'port_dns_over_quic';

export type ServerSettingsField = 'server_names' | PortField;

export type ServerSettingsValues = Pick<EncryptionFormValues, ServerSettingsField>;

/**
 * Client-side rules for a single port input: the valid range plus the
 * browser-unsafe ports, which only apply to the HTTPS port.
 */
export const validatePortField = (field: PortField, value?: number): string | undefined =>
    validatePort(value) || (field === 'port_https' ? validateIsSafePort(value) : undefined);

/**
 * Client-side validation for the encrypted DNS server settings — the server
 * names and the three ports.  Shared by the TLS setup wizard's config step and
 * the encrypted DNS server settings dialog, so both hosts accept and reject
 * exactly the same values.
 */
export const validateServerSettings = (
    values: ServerSettingsValues,
    externalPorts?: ExternalPorts,
): Record<string, string> => {
    const errs: Record<string, string> = {};

    // Server names — optional, format only.
    const names = values.server_names || [];
    if (names.some((name) => validateServerName(name))) {
        errs.server_names = intl.getMessage('form_error_server_name');
    }

    // Ports — range, unsafe, and collisions with each other and with the ports
    // owned by the other AdGuard Home settings.
    for (const field of ['port_https', 'port_dns_over_tls', 'port_dns_over_quic'] as PortField[]) {
        const error = validatePortField(field, Number(values[field]) || 0);
        if (error) errs[field] = error;
    }
    Object.assign(errs, validatePortConflicts(values, externalPorts));

    return errs;
};

/**
 * Runs all client-side validation for the encryption form and returns a map of
 * field name -> error message. An empty object means the form is valid.
 *
 * Used by both `handleBlur` (to gate the debounced backend validate request)
 * and `onFormSubmit`, so the rules live in one place.
 */
export const validateEncryptionForm = (
    values: EncryptionFormValues,
    externalPorts?: ExternalPorts,
): Record<string, string> => {
    const errs: Record<string, string> = {};

    // Delegate cert/key validation to the shared helper.
    Object.assign(errs, validateCertKeyFields(values));

    // Server names — optional, format only.
    const serverNames = values.server_names || [];
    const invalidServerName = serverNames.find((name) => validateServerName(name));
    if (invalidServerName !== undefined) {
        errs.server_names = intl.getMessage('form_error_server_name');
    }

    // Insecure (unencrypted) DoH — must stay enabled when encryption is off.
    const insecureEnabledErr = validateInsecureEnabled(values.insecure_enabled, values);
    if (insecureEnabledErr) errs.insecure_enabled = insecureEnabledErr;

    // Ports — range, unsafe, and equality are checked fully client-side so
    // invalid ports never reach the backend validate request.
    // Coerce to number first: the store may hold empty strings before the
    // first data load, and `validatePort('')` would skip the range check.
    const portHttps = Number(values.port_https) || 0;
    const portDot = Number(values.port_dns_over_tls) || 0;
    const portDoq = Number(values.port_dns_over_quic) || 0;

    const portHttpsErr = validatePort(portHttps) || validateIsSafePort(portHttps);
    if (portHttpsErr) errs.port_https = portHttpsErr as string;

    const portDotErr = validatePort(portDot);
    if (portDotErr) errs.port_dns_over_tls = portDotErr as string;

    const portDoqErr = validatePort(portDoq);
    if (portDoqErr) errs.port_dns_over_quic = portDoqErr as string;

    // Ports may not collide with each other or with the ports owned by the
    // other AdGuard Home settings — same families the backend checks.
    Object.assign(errs, validatePortConflicts(values, externalPorts));

    // Plain DNS must be served when encryption is disabled.
    const plainDnsErr = validatePlainDns(values.serve_plain_dns ?? false, values);
    if (plainDnsErr) errs.serve_plain_dns = plainDnsErr as string;

    return errs;
};

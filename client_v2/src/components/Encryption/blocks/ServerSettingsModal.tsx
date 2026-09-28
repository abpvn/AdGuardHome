import { createEffect, createSignal, on } from 'solid-js';
import { createStore } from 'solid-js/store';

import { ConfigDialog } from 'panel/common/ui/ConfigDialog';
import intl from 'panel/common/intl';
import { normalizeServerName, toNumber } from 'panel/helpers/form';
import { validateServerName } from 'panel/helpers/validators';
import { encryptionState, setTlsConfig } from 'panel/stores/encryption';
import {
    validatePortField,
    validateServerSettings,
    type ServerSettingsField,
    type ServerSettingsValues,
} from '../validate';
import { getExternalPorts } from './helpers';
import { ServerSettingsFields, type ServerSettingsValue } from './ServerSettingsFields';
import { createServerNameCheck } from './useServerNameCheck';

type Props = {
    open: boolean;
    onClose: () => void;
};

const defaults: ServerSettingsValues = {
    server_names: [''],
    port_https: 0,
    port_dns_over_tls: 0,
    port_dns_over_quic: 0,
};

export const ServerSettingsModal = (props: Props) => {
    const [values, setValues] = createStore<ServerSettingsValues>({ ...defaults });
    const [errors, setErrors] = createSignal<Record<string, string>>({});

    const nameCheck = createServerNameCheck({ values });

    createEffect(
        on(
            () => props.open,
            (open) => {
                if (!open) return;

                const names = (encryptionState.server_names || []).filter((name) => !!name);
                setValues({
                    server_names: names.length > 0 ? [...names] : [''],
                    port_https: Number(encryptionState.port_https) || 0,
                    port_dns_over_tls: Number(encryptionState.port_dns_over_tls) || 0,
                    port_dns_over_quic: Number(encryptionState.port_dns_over_quic) || 0,
                });
                setErrors({});
                nameCheck.reset(names);
            },
        ),
    );

    /** Errors that follow from the current values, e.g. a port conflict. */
    const clientErrors = () => validateServerSettings(values, getExternalPorts());

    const setFieldError = (field: string, message?: string) => {
        setErrors((prev) => {
            const next = { ...prev };
            if (message) {
                next[field] = message;
            } else {
                delete next[field];
            }
            return next;
        });
    };

    /**
     * Error to render under a field: blur/submit errors win, then the live
     * client-side rules.  Only the ports have live rules — a server name is
     * validated on blur and by the backend, so typing does not flash an error
     * mid-word.
     */
    const fieldError = (field: ServerSettingsField) => {
        if (field === 'server_names') return undefined;
        return errors()[field] ?? clientErrors()[field];
    };

    const serverNameError = (index: number) => errors()[`server_name_${index}`];

    const handleFieldChange = (field: ServerSettingsField, value: ServerSettingsValue) => {
        if (field === 'server_names') {
            const names = value as string[];
            setValues('server_names', names);
            // The clear button reports through `change` only, so this is what
            // keeps the live names in step there.
            nameCheck.onNameInput(names);
            setErrors((prev) => {
                const next = { ...prev };
                names.forEach((_, index) => delete next[`server_name_${index}`]);
                return next;
            });
            return;
        }
        setFieldError(field);
        setValues(field, toNumber(value as string));
    };

    /** Typing invalidates the warning: it belongs to the names it was reported for. */
    const handleFieldInput = (field: ServerSettingsField, value: ServerSettingsValue) => {
        if (field === 'server_names') nameCheck.onNameInput(value as string[]);
    };

    const handleFieldBlur = (field: ServerSettingsField) => {
        if (field === 'server_names') {
            const names = (values.server_names ?? []).map(normalizeServerName);
            setValues('server_names', names);
            nameCheck.onNameInput(names);

            let firstInvalid = -1;
            names.forEach((name, index) => {
                const error = validateServerName(name);
                setFieldError(`server_name_${index}`, error);
                if (error && firstInvalid === -1) firstInvalid = index;
            });

            if (firstInvalid === -1) nameCheck.checkOnBlur(names);
            return;
        }

        const port = Number(values[field]) || 0;
        setFieldError(field, validatePortField(field, port));
    };

    const addServerName = () => {
        setValues('server_names', [...(values.server_names ?? []), '']);
        nameCheck.onNameInput(values.server_names);
    };

    const removeServerName = (index: number) => {
        setValues(
            'server_names',
            (values.server_names ?? []).filter((_, i) => i !== index),
        );
        setFieldError(`server_name_${index}`);
        nameCheck.onNameInput(values.server_names);
    };

    const save = async () => {
        const errs = clientErrors();
        if (Object.values(errs).some(Boolean)) {
            setErrors(errs);
            return;
        }

        if (!(await nameCheck.confirmSave())) return;

        setTlsConfig({ ...values });
        props.onClose();
    };

    const processing = () => encryptionState.processingConfig || encryptionState.processingValidate;
    const hasErrors = () =>
        Object.values(errors()).some(Boolean) || Object.values(clientErrors()).some(Boolean);

    return (
        <ConfigDialog
            open={props.open}
            title={intl.getMessage('encrypted_dns_settings')}
            onClose={props.onClose}
            onSubmit={save}
            processing={processing()}
            submitDisabled={processing() || hasErrors()}
            buttonText={nameCheck.warningText() ? intl.getMessage('save_anyway') : undefined}
            buttonVariant={nameCheck.warningText() ? 'warning' : undefined}
        >
            <ServerSettingsFields
                values={values}
                onFieldChange={handleFieldChange}
                onFieldInput={handleFieldInput}
                onFieldBlur={handleFieldBlur}
                onAddServerName={addServerName}
                onRemoveServerName={removeServerName}
                errorFor={fieldError}
                serverNameErrorFor={serverNameError}
                warningFor={(field) =>
                    field === 'server_names' ? nameCheck.warningText() : undefined
                }
                testIdPrefix="server-settings"
                clearable
            />
        </ConfigDialog>
    );
};

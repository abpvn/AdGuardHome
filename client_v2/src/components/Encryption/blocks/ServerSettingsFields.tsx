import { Index, Show, type JSX } from 'solid-js';
import cn from 'clsx';

import { Input } from 'panel/common/controls/Input';
import { Button } from 'panel/common/ui/Button';
import { Icon } from 'panel/common/ui/Icon';
import { FaqTooltip } from 'panel/common/ui/FaqTooltip';
import intl from 'panel/common/intl';
import theme from 'panel/lib/theme';
import {
    DNS_OVER_QUIC_PORT,
    DNS_OVER_TLS_PORT,
    STANDARD_HTTPS_PORT,
} from 'panel/helpers/constants';
import type { PortField, ServerSettingsField, ServerSettingsValues } from '../validate';
import s from '../styles.module.pcss';

/** A text field carries a string; the server-name list carries the whole array. */
export type ServerSettingsValue = string | string[];

type Props = {
    values: ServerSettingsValues;
    onFieldChange: (field: ServerSettingsField, value: ServerSettingsValue) => void;
    onFieldBlur: (field: ServerSettingsField) => void;
    onFieldInput?: (field: ServerSettingsField, value: ServerSettingsValue) => void;
    /** Adds an empty server-name row. */
    onAddServerName?: () => void;
    /** Removes the server-name row at `index`. */
    onRemoveServerName?: (index: number) => void;
    errorFor?: (field: ServerSettingsField) => string | undefined;
    /** Error for one server-name row, keyed by its index. */
    serverNameErrorFor?: (index: number) => string | undefined;
    warningFor?: (field: ServerSettingsField) => string | undefined;
    idPrefix?: string;
    testIdPrefix?: string;
    clearable?: boolean;
};

type PortInputProps = {
    id: string;
    name: PortField;
    label: JSX.Element;
    value?: number | string;
    onChange: (e: Event) => void;
    onBlur: () => void;
    errorMessage?: string;
    warning?: string;
    clearable?: boolean;
    testId?: string;
};

const FieldWarning = (props: { text?: string; testId?: string }) => (
    <Show when={props.text}>
        <div
            class={cn(theme.text.t3, theme.status.statusYellow, s.fieldWarning)}
            data-testid={props.testId}
        >
            {props.text}
        </div>
    </Show>
);

const PortInput = (props: PortInputProps) => (
    <div class={theme.form.input}>
        <Input
            id={props.id}
            name={props.name}
            type="number"
            value={props.value ?? ''}
            onChange={props.onChange}
            onBlur={props.onBlur}
            isClearable={props.clearable}
            label={props.label}
            errorMessage={props.errorMessage}
            size="large"
            onCard
            data-testid={props.testId}
        />
        <FieldWarning
            text={props.warning}
            testId={props.testId ? `${props.testId}-warning` : undefined}
        />
    </div>
);

/**
 * Server names and the three encrypted DNS ports — the settings shared by the
 * TLS setup wizard's config step and the "Encrypted DNS server settings"
 * dialog.
 *
 * The certificate is checked against every name, so the list is edited as a
 * whole here: the host owns the add/remove bookkeeping and reports the array
 * back through `onFieldChange('server_names', names)`.
 */
export const ServerSettingsFields = (props: Props) => {
    const id = (field: ServerSettingsField) => `${props.idPrefix ?? ''}${field}`;
    const error = (field: ServerSettingsField) => props.errorFor?.(field);
    const warning = (field: ServerSettingsField) => props.warningFor?.(field);
    const testId = (field: string) =>
        props.testIdPrefix ? `${props.testIdPrefix}-${field}` : undefined;

    const names = () => props.values.server_names?.length ? props.values.server_names : [''];

    /** Replaces one row, leaving the rest of the list untouched. */
    const setNameAt = (index: number, value: string) => {
        props.onFieldChange(
            'server_names',
            names().map((name, i) => (i === index ? value : name)),
        );
    };

    return (
        <>
            <div class={theme.form.input}>
                {/* `Index`, not `For`: the rows are keyed by position and their
                    values change as the user types, so the inputs must be
                    updated in place — `For` would recreate the row and drop the
                    caret with it. */}
                <Index each={names()}>
                    {(name, index) => (
                        <div class={s.serverNameRow}>
                            <Input
                                id={`${id('server_names')}-${index}`}
                                name="server_names"
                                value={name()}
                                onChange={(e) =>
                                    setNameAt(index, (e.target as HTMLInputElement).value)
                                }
                                onInput={(e) =>
                                    props.onFieldInput?.('server_names', [
                                        ...names().slice(0, index),
                                        (e.currentTarget as HTMLInputElement).value,
                                        ...names().slice(index + 1),
                                    ])
                                }
                                onBlur={() => props.onFieldBlur('server_names')}
                                isClearable={props.clearable}
                                label={
                                    <>
                                        {intl.getMessage('encryption_server')}
                                        <FaqTooltip
                                            menuSize="large"
                                            text={
                                                <div class={s.tooltipText}>
                                                    {intl.getMessage('encryption_server_tooltip')}
                                                </div>
                                            }
                                        />
                                    </>
                                }
                                placeholder={intl.getMessage('encryption_server_enter')}
                                errorMessage={props.serverNameErrorFor?.(index)}
                                size="large"
                                onCard
                                data-testid={
                                    props.testIdPrefix
                                        ? `${props.testIdPrefix}-server-name-${index}`
                                        : undefined
                                }
                            />
                            <Show when={index > 0 && props.onRemoveServerName}>
                                <button
                                    type="button"
                                    class={s.removeServerNameButton}
                                    onClick={() => props.onRemoveServerName?.(index)}
                                    aria-label={intl.getMessage('remove_server_name')}
                                    title={intl.getMessage('remove_server_name')}
                                >
                                    <Icon icon="cross" />
                                </button>
                            </Show>
                        </div>
                    )}
                </Index>
                <Show when={props.onAddServerName}>
                    <Button
                        variant="secondary"
                        size="small"
                        onClick={() => props.onAddServerName?.()}
                        class={s.addServerNameButton}
                    >
                        <Icon icon="plus" />
                        {intl.getMessage('add_server_name')}
                    </Button>
                </Show>
                <FieldWarning
                    text={warning('server_names')}
                    testId={
                        props.testIdPrefix
                            ? `${props.testIdPrefix}-server-names-warning`
                            : undefined
                    }
                />
            </div>

            <PortInput
                id={id('port_https')}
                name="port_https"
                label={
                    <>
                        {intl.getMessage('encryption_https')}
                        <FaqTooltip
                            menuSize="large"
                            text={intl.getMessage('encryption_https_tooltip', {
                                port: STANDARD_HTTPS_PORT,
                            })}
                        />
                    </>
                }
                value={props.values.port_https}
                onChange={(e) =>
                    props.onFieldChange('port_https', (e.target as HTMLInputElement).value)
                }
                onBlur={() => props.onFieldBlur('port_https')}
                errorMessage={error('port_https')}
                warning={warning('port_https')}
                clearable={props.clearable}
                testId={testId('port-https')}
            />

            <PortInput
                id={id('port_dns_over_tls')}
                name="port_dns_over_tls"
                label={
                    <>
                        {intl.getMessage('encryption_dot')}
                        <FaqTooltip
                            menuSize="large"
                            text={intl.getMessage('encryption_dot_tooltip', {
                                port: DNS_OVER_TLS_PORT,
                            })}
                        />
                    </>
                }
                value={props.values.port_dns_over_tls}
                onChange={(e) =>
                    props.onFieldChange('port_dns_over_tls', (e.target as HTMLInputElement).value)
                }
                onBlur={() => props.onFieldBlur('port_dns_over_tls')}
                errorMessage={error('port_dns_over_tls')}
                warning={warning('port_dns_over_tls')}
                clearable={props.clearable}
                testId={testId('port-dns-over-tls')}
            />

            <PortInput
                id={id('port_dns_over_quic')}
                name="port_dns_over_quic"
                label={
                    <>
                        {intl.getMessage('encryption_doq')}
                        <FaqTooltip
                            menuSize="large"
                            text={intl.getMessage('encryption_doq_tooltip', {
                                port: DNS_OVER_QUIC_PORT,
                            })}
                        />
                    </>
                }
                value={props.values.port_dns_over_quic}
                onChange={(e) =>
                    props.onFieldChange('port_dns_over_quic', (e.target as HTMLInputElement).value)
                }
                onBlur={() => props.onFieldBlur('port_dns_over_quic')}
                errorMessage={error('port_dns_over_quic')}
                warning={warning('port_dns_over_quic')}
                clearable={props.clearable}
                testId={testId('port-dns-over-quic')}
            />
        </>
    );
};

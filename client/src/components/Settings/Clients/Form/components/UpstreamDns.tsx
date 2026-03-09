import React from 'react';
import { Trans, useTranslation } from 'react-i18next';

import { Controller, useFormContext } from 'react-hook-form';
import Examples from '../../../Dns/Upstream/Examples';
import { UINT32_RANGE } from '../../../../../helpers/constants';
import { Textarea } from '../../../../ui/Controls/Textarea';
import { ClientForm } from '../types';
import { Checkbox } from '../../../../ui/Controls/Checkbox';
import { Input } from '../../../../ui/Controls/Input';
import { toNumber } from '../../../../../helpers/form';

type UpstreamDnsProps = {
    canClearCache: boolean;
    onClearClientCache: (name: string) => void;
};

export const UpstreamDns = ({ canClearCache, onClearClientCache }: UpstreamDnsProps) => {
    const { t } = useTranslation();

    const { control, watch } = useFormContext<ClientForm>();
    const upstreamsCacheEnabled = watch('upstreams_cache_enabled');
    const upstreamsCacheSize = watch('upstreams_cache_size');
    const clientName = watch('name');

    const canShowClearCacheButton = canClearCache && upstreamsCacheEnabled && Number(upstreamsCacheSize) > 0;

    const handleClearClientCache = () => {
        if (!clientName) {
            return;
        }

        // eslint-disable-next-line no-alert
        if (window.confirm(t('confirm_client_dns_cache_clear', { key: clientName }))) {
            onClearClientCache(clientName);
        }
    };

    return (
        <div title={t('upstream_dns')}>
            <div className="form__desc mb-3">
                <Trans components={[<a href="#dns" key="0" />]}>upstream_dns_client_desc</Trans>
            </div>

            <Controller
                name="upstreams"
                control={control}
                render={({ field }) => (
                    <Textarea
                        {...field}
                        data-testid="clients_upstreams"
                        className="form-control form-control--textarea mb-5"
                        placeholder={t('upstream_dns')}
                        trimOnBlur
                    />
                )}
            />

            <Examples />

            <div className="form__label--bold mt-5 mb-3">{t('upstream_dns_cache_configuration')}</div>

            <div className="form__group mb-2">
                <Controller
                    name="upstreams_cache_enabled"
                    control={control}
                    render={({ field }) => (
                        <Checkbox
                            {...field}
                            data-testid="clients_upstreams_cache_enabled"
                            title={t('enable_upstream_dns_cache')}
                        />
                    )}
                />
            </div>

            <div className="form__group form__group--settings">
                <label htmlFor="upstreams_cache_size" className="form__label">
                    {t('dns_cache_size')}
                </label>

                <Controller
                    name="upstreams_cache_size"
                    control={control}
                    render={({ field, fieldState }) => (
                        <Input
                            {...field}
                            type="number"
                            data-testid="clients_upstreams_cache_size"
                            placeholder={t('enter_cache_size')}
                            error={fieldState.error?.message}
                            min={0}
                            max={UINT32_RANGE.MAX}
                            onChange={(e) => {
                                const { value } = e.target;
                                field.onChange(toNumber(value));
                            }}
                        />
                    )}
                />
            </div>

            {canShowClearCacheButton && (
                <button
                    type="button"
                    data-testid="clients_clear_cache"
                    className="btn btn-outline-secondary btn-standard"
                    onClick={handleClearClientCache}>
                    {t('clear_cache')}
                </button>
            )}
        </div>
    );
};

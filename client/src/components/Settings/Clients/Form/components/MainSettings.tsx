import React from 'react';
import { useTranslation } from 'react-i18next';
import { Controller, useFormContext } from 'react-hook-form';
import { captitalizeWords } from '../../../../../helpers/helpers';
import { ClientForm } from '../types';
import { Checkbox } from '../../../../ui/Controls/Checkbox';

type ProtectionSettings = 'use_global_settings' | 'filtering_enabled' | 'safebrowsing_enabled' | 'parental_enabled';

const settingsCheckboxes: {
    name: ProtectionSettings;
    placeholder: string;
}[] = [
    {
        name: 'use_global_settings',
        placeholder: 'client_global_settings',
    },
    {
        name: 'filtering_enabled',
        placeholder: 'block_domain_use_filters_and_hosts',
    },
    {
        name: 'safebrowsing_enabled',
        placeholder: 'use_adguard_browsing_sec',
    },
    {
        name: 'parental_enabled',
        placeholder: 'use_adguard_parental',
    },
];

type FiltersSettings = 'use_global_filters';

const filtersCheckboxes: {
    name: FiltersSettings;
    placeholder: string;
}[] = [
    {
        name: 'use_global_filters',
        placeholder: 'use_global_filters',
    },
];

type LogsStatsSettings = 'ignore_querylog' | 'ignore_statistics';

const logAndStatsCheckboxes: { name: LogsStatsSettings; placeholder: string }[] = [
    {
        name: 'ignore_querylog',
        placeholder: 'ignore_query_log',
    },
    {
        name: 'ignore_statistics',
        placeholder: 'ignore_statistics',
    },
];

type Props = {
    safeSearchServices: Record<string, boolean>;
};

export const MainSettings = ({ safeSearchServices }: Props) => {
    const { t } = useTranslation();
    const { watch, control } = useFormContext<ClientForm>();

    const useGlobalSettings = watch('use_global_settings');

    return (
        <div title={t('main_settings')}>
            <div className="form__label--bot form__label--bold">{t('filters')}</div>
            {filtersCheckboxes.map((setting) => (
                <div className="form__group" key={setting.name}>
                    <Controller
                        name={setting.name}
                        control={control}
                        render={({ field }) => (
                            <Checkbox {...field} data-testid={`clients_${setting.name}`} title={t(setting.placeholder)} />
                        )}
                    />
                </div>
            ))}
            <div className="form__label--bot form__label--bold">{t('protection_section_label')}</div>
            {settingsCheckboxes.map((setting) => (
                <div className="form__group" key={setting.name}>
                    <Controller
                        name={setting.name}
                        control={control}
                        render={({ field }) => (
                            <Checkbox
                                {...field}
                                data-testid={`clients_${setting.name}`}
                                title={t(setting.placeholder)}
                                disabled={setting.name !== 'use_global_settings' ? useGlobalSettings : false}
                            />
                        )}
                    />
                </div>
            ))}

            <div className="form__group">
                <Controller
                    name="safe_search.enabled"
                    control={control}
                    render={({ field }) => (
                        <Checkbox
                            data-testid="clients_safe_search"
                            {...field}
                            title={t('enforce_safe_search')}
                            disabled={useGlobalSettings}
                        />
                    )}
                />
            </div>

            <div className="form__group--inner">
                {Object.keys(safeSearchServices).map((searchKey) => (
                    <div key={searchKey}>
                        <Controller
                            name={`safe_search.${searchKey}`}
                            control={control}
                            render={({ field }) => (
                                <Checkbox
                                    {...field}
                                    data-testid={`clients_safe_search_${searchKey}`}
                                    title={captitalizeWords(searchKey)}
                                    disabled={useGlobalSettings}
                                />
                            )}
                        />
                    </div>
                ))}
            </div>

            <div className="form__label--bold form__label--top form__label--bot">
                {t('log_and_stats_section_label')}
            </div>
            {logAndStatsCheckboxes.map((setting) => (
                <div className="form__group" key={setting.name}>
                    <Controller
                        name={setting.name}
                        control={control}
                        render={({ field }) => (
                            <Checkbox {...field} data-testid={`clients_${setting.name}`} title={t(setting.placeholder)} />
                        )}
                    />
                </div>
            ))}
        </div>
    );
};

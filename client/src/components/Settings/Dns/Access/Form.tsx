import React, { ReactNode, useEffect } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { Trans, useTranslation } from 'react-i18next';

import i18next from 'i18next';
import { CLIENT_ID_LINK } from '../../../../helpers/constants';
import { removeEmptyLines, trimMultilineString } from '../../../../helpers/helpers';
import { Textarea } from '../../../ui/Controls/Textarea';

type FormData = {
    allowed_clients: string;
    disallowed_clients: string;
    blocked_hosts: string;
    allowed_countries: string;
    blocked_countries: string;
};

const fields: {
    id: keyof FormData;
    title: string;
    subtitle: ReactNode;
    placeholder?: string;
    normalizeOnBlur: (value: string) => string;
}[] = [
    {
        id: 'allowed_clients',
        title: i18next.t('access_allowed_title'),
        subtitle: (
            <Trans
                components={{
                    a: <a href={CLIENT_ID_LINK} target="_blank" rel="noopener noreferrer" />,
                }}>
                access_allowed_desc
            </Trans>
        ),
        normalizeOnBlur: removeEmptyLines,
    },
    {
        id: 'disallowed_clients',
        title: i18next.t('access_disallowed_title'),
        subtitle: (
            <Trans
                components={{
                    a: <a href={CLIENT_ID_LINK} target="_blank" rel="noopener noreferrer" />,
                }}>
                access_disallowed_desc
            </Trans>
        ),
        normalizeOnBlur: trimMultilineString,
    },
    {
        id: 'blocked_hosts',
        title: i18next.t('access_blocked_title'),
        subtitle: i18next.t('access_blocked_desc'),
        normalizeOnBlur: removeEmptyLines,
    },
    {
        id: 'allowed_countries',
        title: i18next.t('allowed_countries_title'),
        subtitle: i18next.t('allowed_countries_desc'),
        placeholder: i18next.t('example_countries_placeholder'),
        normalizeOnBlur: (text: string) => removeEmptyLines(text.toUpperCase()),
    },
    {
        id: 'blocked_countries',
        title: i18next.t('blocked_countries_title'),
        subtitle: i18next.t('blocked_countries_desc'),
        placeholder: i18next.t('example_countries_placeholder'),
        normalizeOnBlur: (text: string) => removeEmptyLines(text.toUpperCase()),
    },
];

type FormProps = {
    initialValues?: {
        allowed_clients?: string;
        disallowed_clients?: string;
        blocked_hosts?: string;
        allowed_countries?: string;
        blocked_countries?: string;
    };
    onSubmit: (data: FormData) => void;
    processingSet: boolean;
};

const Form = ({ initialValues, onSubmit, processingSet }: FormProps) => {
    const { t } = useTranslation();

    const {
        control,
        handleSubmit,
        watch,
        formState: { isSubmitting, isDirty, isSubmitSuccessful },
        reset
    } = useForm<FormData>({
        mode: 'onBlur',
        defaultValues: {
            allowed_clients: initialValues?.allowed_clients || '',
            disallowed_clients: initialValues?.disallowed_clients || '',
            blocked_hosts: initialValues?.blocked_hosts || '',
            allowed_countries: initialValues?.allowed_countries || '',
            blocked_countries: initialValues?.blocked_countries || '',
        },
    });

    useEffect(() => {
        if (isSubmitSuccessful) {
            reset(watch(), {keepValues: true, keepDirty: false, keepDefaultValues: false});
        }
    }, [isSubmitSuccessful, reset]);

    const allowedClients = watch('allowed_clients');
    const allowedCountries = watch('allowed_countries');

    const renderField = ({
        id,
        title,
        subtitle,
        placeholder,
        normalizeOnBlur,
    }: {
        id: keyof FormData;
        title: string;
        subtitle: ReactNode;
        placeholder?: string;
        normalizeOnBlur: (value: string) => string;
    }) => {
        const disabled = (allowedClients && id === 'disallowed_clients') || (allowedCountries && id === 'blocked_countries');

        return (
            <div key={id} className="form__group mb-5">
                <label className="form__label form__label--with-desc" htmlFor={id}>
                    {title}
                    {disabled && <>&nbsp;({t('disabled')})</>}
                </label>

                <div className="form__desc form__desc--top">{subtitle}</div>

                <Controller
                    name={id}
                    control={control}
                    render={({ field }) => (
                        <Textarea
                            {...field}
                            id={id}
                            data-testid={id}
                            disabled={disabled || processingSet}
                            placeholder={placeholder}
                            onBlur={(e) => {
                                field.onChange(normalizeOnBlur(e.target.value));
                            }}
                        />
                    )}
                />
            </div>
        );
    };

    return (
        <form onSubmit={handleSubmit(onSubmit)}>
            {fields.map((f) => renderField(f))}

            <div className="card-actions">
                <div className="btn-list">
                    <button
                        type="submit"
                        data-testid="access_save"
                        className="btn btn-success btn-standard"
                        disabled={isSubmitting || !isDirty || processingSet}>
                        {t('save_config')}
                    </button>
                </div>
            </div>
        </form>
    );
};

export default Form;

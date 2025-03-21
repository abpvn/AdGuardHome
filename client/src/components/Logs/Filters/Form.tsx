import React, { useEffect } from 'react';

import { useTranslation } from 'react-i18next';
import { useDispatch, useSelector } from 'react-redux';

import { useHistory } from 'react-router-dom';
import classNames from 'classnames';
import { useFormContext } from 'react-hook-form';
import queryString from 'query-string';

import {
    DEBOUNCE_FILTER_TIMEOUT,
    DEFAULT_LOGS_FILTER,
    RESPONSE_FILTER,
    RESPONSE_FILTER_QUERIES,
} from '../../../helpers/constants';
import { setLogsFilter } from '../../../actions/queryLogs';
import useDebounce from '../../../helpers/useDebounce';

import { getLogsUrlParams } from '../../../helpers/helpers';

import { Client, RootState } from '../../../initialState';
import { SearchField } from './SearchField';
import { SearchFormValues } from '..';

type Props = {
    className?: string;
    setIsLoading: (value: boolean) => void;
};

export const Form = ({ className, setIsLoading }: Props) => {
    const { t } = useTranslation();
    const dispatch = useDispatch();
    const history = useHistory();
    const clients = useSelector((state: RootState) => state.dashboard.clients);

    const { register, watch, setValue } = useFormContext<SearchFormValues>();

    const searchValue = watch('search');
    const responseStatusValue = watch('response_status');
    const client = watch('client');

    const [debouncedSearch, setDebouncedSearch] = useDebounce(searchValue.trim(), DEBOUNCE_FILTER_TIMEOUT);

    useEffect(() => {
        dispatch(
            setLogsFilter({
                response_status: responseStatusValue,
                search: debouncedSearch,
                client,
            }),
        );

        history.replace(`${getLogsUrlParams(debouncedSearch, responseStatusValue, client)}`);
    }, [responseStatusValue, debouncedSearch, client]);

    useEffect(() => {
        if (responseStatusValue && !(responseStatusValue in RESPONSE_FILTER_QUERIES)) {
            setValue('response_status', DEFAULT_LOGS_FILTER.response_status);
        }
    }, [responseStatusValue, setValue]);

    useEffect(() => {
        const { search: searchUrlParam } = queryString.parse(history.location.search);

        if (searchUrlParam !== searchValue) {
            setValue('search', searchUrlParam ? searchUrlParam.toString() : '');
        }
    }, [history.location.search]);

    const onInputClear = async () => {
        setIsLoading(true);
        history.push(getLogsUrlParams(DEFAULT_LOGS_FILTER.search, responseStatusValue));
        setIsLoading(false);
    };

    const onEnterPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Enter') {
            setDebouncedSearch(searchValue);
        }
    };

    return (
        <form
            className="d-flex flex-wrap form-control--container"
            onSubmit={(e) => {
                e.preventDefault();
            }}>
            <div className="field__search">
                <SearchField
                    value={searchValue}
                    handleChange={(val) => setValue('search', val)}
                    onKeyDown={onEnterPress}
                    onClear={onInputClear}
                    placeholder={t('domain_or_client')}
                    tooltip={t('query_log_strict_search')}
                    className={classNames('form-control form-control--search form-control--transparent', className)}
                />
            </div>
            <div className="field__select">
                <select
                    {...register('response_status')}
                    className="form-control custom-select custom-select--logs custom-select__arrow--left form-control--transparent d-sm-block">
                    {Object.values(RESPONSE_FILTER).map(({ QUERY, LABEL, disabled }: any) => (
                        <option key={LABEL} value={QUERY} disabled={disabled}>
                            {t(LABEL)}
                        </option>
                    ))}
                </select>
            </div>
            <div className="field__select">
                <select
                    {...register('client')}
                    className="form-control custom-select custom-select--logs custom-select__arrow--left form-control--transparent d-sm-block">
                    <option value="">{t('all_client')}</option>
                    {clients.map(({ name }: Client) => (
                        <option key={name} value={name}>
                            {name}
                        </option>
                    ))}
                </select>
            </div>
        </form>
    );
};

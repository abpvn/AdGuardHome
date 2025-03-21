import { createAction } from 'redux-actions';
import i18next from 'i18next';

import apiClient from '../api/Api';
import { addErrorToast, addSuccessToast } from './toasts';
import { COUNTRY_PREFIX } from '../helpers/constants';

import { splitByNewLine } from '../helpers/helpers';

export const getAccessListRequest = createAction('GET_ACCESS_LIST_REQUEST');
export const getAccessListFailure = createAction('GET_ACCESS_LIST_FAILURE');
export const getAccessListSuccess = createAction('GET_ACCESS_LIST_SUCCESS');

export const getAccessList = () => async (dispatch: any) => {
    dispatch(getAccessListRequest());
    try {
        const data = await apiClient.getAccessList();
        dispatch(getAccessListSuccess(data));
    } catch (error) {
        dispatch(addErrorToast({ error }));
        dispatch(getAccessListFailure());
    }
};

export const setAccessListRequest = createAction('SET_ACCESS_LIST_REQUEST');
export const setAccessListFailure = createAction('SET_ACCESS_LIST_FAILURE');
export const setAccessListSuccess = createAction('SET_ACCESS_LIST_SUCCESS');

export const setAccessList = (config: any) => async (dispatch: any) => {
    dispatch(setAccessListRequest());
    try {
        const { allowed_clients, disallowed_clients, blocked_hosts, blocked_countries, allowed_countries } = config;

        const values = {
            allowed_clients: splitByNewLine(allowed_clients),
            disallowed_clients: splitByNewLine(disallowed_clients),
            blocked_hosts: splitByNewLine(blocked_hosts),
            blocked_countries: splitByNewLine(blocked_countries),
            allowed_countries: splitByNewLine(allowed_countries),
        };

        await apiClient.setAccessList(values);
        dispatch(setAccessListSuccess());
        dispatch(addSuccessToast('access_settings_saved'));
    } catch (error) {
        dispatch(addErrorToast({ error }));
        dispatch(setAccessListFailure());
    }
};

export const toggleClientBlockRequest = createAction('TOGGLE_CLIENT_BLOCK_REQUEST');
export const toggleClientBlockFailure = createAction('TOGGLE_CLIENT_BLOCK_FAILURE');
export const toggleClientBlockSuccess = createAction('TOGGLE_CLIENT_BLOCK_SUCCESS');

export const toggleClientBlock = (ip: any, disallowed: any, disallowed_rule: string) => async (dispatch: any) => {
    dispatch(toggleClientBlockRequest());
    try {
        const accessList = await apiClient.getAccessList();
        const blocked_hosts = accessList.blocked_hosts ?? [];
        let allowed_clients = accessList.allowed_clients ?? [];
        let disallowed_clients = accessList.disallowed_clients ?? [];
        let blocked_countries = accessList.blocked_countries ?? [];
        const allowed_countries = accessList.allowed_countries ?? [];

        if (disallowed) {
            if (!disallowed_rule) {
                allowed_clients = allowed_clients.concat(ip);
            } else if (disallowed_rule.startsWith(COUNTRY_PREFIX)) {
                const un_blocked_country = disallowed_rule.split(':')[1];
                blocked_countries = blocked_countries.filter((country: any) => country !== un_blocked_country);
            } else {
                disallowed_clients = disallowed_clients.filter((client: any) => client !== disallowed_rule);
            }
        } else if (allowed_clients.length > 1) {
            allowed_clients = allowed_clients.filter((client: any) => client !== disallowed_rule);
        } else {
            disallowed_clients = disallowed_clients.concat(ip);
        }
        const values = {
            allowed_clients,
            blocked_hosts,
            disallowed_clients,
            blocked_countries,
            allowed_countries,
        };

        await apiClient.setAccessList(values);
        dispatch(toggleClientBlockSuccess(values));

        if (disallowed) {
            if (disallowed_rule.startsWith(COUNTRY_PREFIX)) {
                const un_blocked_country = disallowed_rule.split(':')[1];
                dispatch(addSuccessToast(i18next.t('client_unblocked_country', { country: un_blocked_country })));
            } else {
                dispatch(addSuccessToast(i18next.t('client_unblocked', { ip: disallowed_rule || ip })));
            }
        } else {
            dispatch(addSuccessToast(i18next.t('client_blocked', { ip })));
        }
    } catch (error) {
        dispatch(addErrorToast({ error }));
        dispatch(toggleClientBlockFailure());
    }
};

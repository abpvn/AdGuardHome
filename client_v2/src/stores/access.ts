import { createStore } from 'solid-js/store';
import { untrack } from 'solid-js';
import { accessList, accessSet } from 'panel/api/generated';
import { addErrorToast, addSuccessToast } from './toasts';
import { splitByNewLine } from 'panel/helpers/helpers';
import { COUNTRY_PREFIX } from 'panel/helpers/constants';
import intl from 'panel/common/intl';
import type { AccessList } from 'panel/api/model/accessList';

type AccessState = {
    processing: boolean;
    initialized: boolean;
    processingSet: boolean;
    allowed_clients: string;
    disallowed_clients: string;
    blocked_hosts: string;
    allowed_countries: string;
    blocked_countries: string;
};

const initialState: AccessState = {
    processing: true,
    initialized: false,
    processingSet: false,
    allowed_clients: '',
    disallowed_clients: '',
    blocked_hosts: '',
    allowed_countries: '',
    blocked_countries: '',
};

const [state, setState] = createStore<AccessState>(initialState);

export const getAccessList = async (): Promise<boolean> => {
    setState('processing', true);
    try {
        const data = await accessList();
        setState({
            allowed_clients: data.allowed_clients?.join('\n') || '',
            disallowed_clients: data.disallowed_clients?.join('\n') || '',
            blocked_hosts: data.blocked_hosts?.join('\n') || '',
            allowed_countries: data.allowed_countries?.join('\n') || '',
            blocked_countries: data.blocked_countries?.join('\n') || '',
            processing: false,
            initialized: true,
        });
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState({ processing: false, initialized: true });
        return false;
    }
};

export const setAccessList = async (values: {
    allowed_clients?: string;
    disallowed_clients?: string;
    blocked_hosts?: string;
    allowed_countries?: string;
    blocked_countries?: string;
}): Promise<boolean> => {
    setState('processingSet', true);
    try {
        // The backend replaces all lists on every save, so an omitted field
        // must keep its current value.  Read it from the server: the store can
        // be empty after a failed initial read.
        const current = await accessList();
        const allowedClients =
            values.allowed_clients ?? (current.allowed_clients ?? []).join('\n');
        const disallowedClients =
            values.disallowed_clients ?? (current.disallowed_clients ?? []).join('\n');
        const blockedHosts = values.blocked_hosts ?? (current.blocked_hosts ?? []).join('\n');
        const allowedCountries =
            values.allowed_countries ?? (current.allowed_countries ?? []).join('\n');
        const blockedCountries =
            values.blocked_countries ?? (current.blocked_countries ?? []).join('\n');

        const allowed = splitByNewLine(allowedClients);
        const disallowed = splitByNewLine(disallowedClients);
        const blocked = splitByNewLine(blockedHosts);
        const allowedCountriesList = splitByNewLine(allowedCountries.toUpperCase());
        const blockedCountriesList = splitByNewLine(blockedCountries.toUpperCase());

        const config: AccessList = {
            allowed_clients: allowed,
            disallowed_clients: disallowed,
            blocked_hosts: blocked,
            allowed_countries: allowedCountriesList,
            blocked_countries: blockedCountriesList,
        };

        await accessSet(config);
        setState({
            allowed_clients: allowed.join('\n'),
            disallowed_clients: disallowed.join('\n'),
            blocked_hosts: blocked.join('\n'),
            allowed_countries: allowedCountriesList.join('\n'),
            blocked_countries: blockedCountriesList.join('\n'),
            processingSet: false,
        });
        addSuccessToast(intl.getMessage('settings_notify_changes_saved'));
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState('processingSet', false);
        return false;
    }
};

const addUnique = (items: string[], value: string) =>
    items.includes(value) ? items : items.concat(value);
const removeValue = (items: string[], value: string) => items.filter((i) => i !== value);

const getNextClientAccessList = ({
    accessList,
    ip,
    disallowed,
    disallowedRule,
}: {
    accessList: AccessList;
    ip: string;
    disallowed: boolean;
    disallowedRule: string;
}) => {
    const values = {
        blocked_hosts: accessList.blocked_hosts ?? [],
        allowed_clients: accessList.allowed_clients ?? [],
        disallowed_clients: accessList.disallowed_clients ?? [],
        blocked_countries: accessList.blocked_countries ?? [],
        allowed_countries: accessList.allowed_countries ?? [],
    };
    const country = disallowedRule.startsWith(COUNTRY_PREFIX)
        ? disallowedRule.split(':')[1]
        : '';
    const isAllowlistMode = values.allowed_clients.length > 0;

    if (disallowed && country) {
        return {
            ...values,
            blocked_countries: removeValue(values.blocked_countries, country),
        };
    }
    if (disallowed && isAllowlistMode) {
        return {
            ...values,
            allowed_clients: addUnique(values.allowed_clients, ip),
        };
    }
    if (disallowed) {
        return {
            ...values,
            disallowed_clients: removeValue(values.disallowed_clients, disallowedRule || ip),
        };
    }
    if (isAllowlistMode) {
        return {
            ...values,
            allowed_clients: removeValue(values.allowed_clients, ip),
        };
    }
    return {
        ...values,
        disallowed_clients: addUnique(values.disallowed_clients, ip),
    };
};

export const toggleClientBlock = async (
    ip: string,
    disallowed: boolean,
    disallowedRule: string,
) => {
    setState('processingSet', true);
    try {
        const accessListData = await accessList();
        const values = getNextClientAccessList({
            accessList: accessListData,
            ip,
            disallowed,
            disallowedRule,
        });
        await accessSet(values);
        setState({
            allowed_clients: values.allowed_clients.join('\n'),
            disallowed_clients: values.disallowed_clients.join('\n'),
            blocked_hosts: values.blocked_hosts.join('\n'),
            allowed_countries: values.allowed_countries.join('\n'),
            blocked_countries: values.blocked_countries.join('\n'),
            processingSet: false,
        });
        if (disallowed) {
            const country = disallowedRule.startsWith(COUNTRY_PREFIX)
                ? disallowedRule.split(':')[1]
                : '';
            addSuccessToast(
                country
                    ? intl.getMessage('client_unblocked_country', { country })
                    : intl.getMessage('client_unblocked_flash'),
            );
        } else {
            addSuccessToast(intl.getMessage('client_blocked_flash'));
        }
    } catch (error) {
        addErrorToast({ error });
        setState('processingSet', false);
    }
};

export const accessState = untrack(() => state);

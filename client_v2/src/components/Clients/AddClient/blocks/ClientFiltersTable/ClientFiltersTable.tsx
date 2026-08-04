import { createMemo, createSignal, Show, untrack } from 'solid-js';
import cn from 'clsx';

import intl from 'panel/common/intl';
import { MODAL_TYPE } from 'panel/helpers/constants';
import theme from 'panel/lib/theme';
import { Icon } from 'panel/common/ui/Icon';
import { PlusButton } from 'panel/common/ui/PlusButton';
import { openModal } from 'panel/stores/modals';
import { clientFormState, updateClientFormField } from 'panel/stores/clientForm';
import { refreshFilters } from 'panel/stores/filtering';
import { clientDetail } from 'panel/api/generated';
import type { Filter } from 'panel/api/model/filter';
import { normalizeFilters } from 'panel/helpers/helpers';
import { ListsTable, TABLE_IDS } from 'panel/components/FilterLists/blocks/ListsTable/ListsTable';

import { ClientFiltersModal } from '../ClientFiltersModal';

import s from './ClientFiltersTable.module.pcss';

type ClientFiltersField = 'filters' | 'whitelist_filters';

type Props = {
    whitelist?: boolean;
    title: string;
    clientName: string;
};

type TableIdsType = 'allowlists_table' | 'blocklists_table';

const TABLE_IDS_BY_FIELD: Record<ClientFiltersField, TableIdsType> = {
    filters: TABLE_IDS.BLOCKLISTS_TABLE,
    whitelist_filters: TABLE_IDS.ALLOWLISTS_TABLE,
};

const getAddModalId = (whitelist: boolean) =>
    whitelist ? MODAL_TYPE.ADD_ALLOWLIST : MODAL_TYPE.ADD_BLOCKLIST;

const getEditModalId = (whitelist: boolean) =>
    whitelist ? MODAL_TYPE.EDIT_ALLOWLIST : MODAL_TYPE.EDIT_BLOCKLIST;

export const ClientFiltersTable = (props: Props) => {
    const field = createMemo<ClientFiltersField>(() => (props.whitelist ? 'whitelist_filters' : 'filters'));

    const [filterToEdit, setFilterToEdit] = createSignal<{
        url: string;
        name: string;
        enabled?: boolean;
    }>({
        url: '',
        name: '',
    });

    const filters = createMemo(() => normalizeFilters(clientFormState[field()] || []));

    const existingUrls = createMemo(() =>
        (clientFormState[field()] || []).map((filter: Filter) => filter.url),
    );

    const handleToggle = (url: string, data: { name: string; url: string; enabled: boolean }) => {
        const list = [...(untrack(() => clientFormState[field()]) || [])];
        const index = list.findIndex((filter: Filter) => filter.url === url);
        if (index !== -1) {
            list[index] = { ...list[index], enabled: data.enabled };
            updateClientFormField(field(), list);
        }
    };

    const handleDelete = (url: string) => {
        const list = [...(untrack(() => clientFormState[field()]) || [])];
        updateClientFormField(
            field(),
            list.filter((filter: Filter) => filter.url !== url),
        );
    };

    const handleAdd = (newFilters: Array<{ name: string; url: string }>) => {
        const list = [...(untrack(() => clientFormState[field()]) || [])];
        newFilters.forEach(({ name, url }) => {
            list.push({ enabled: true, name, url, rules_count: 0, id: 0 });
        });
        updateClientFormField(field(), list);
    };

    const handleEdit = (
        currentUrl: string,
        values: { name: string; url: string; enabled: boolean },
    ) => {
        const list = [...(untrack(() => clientFormState[field()]) || [])];
        const index = list.findIndex((filter: Filter) => filter.url === currentUrl);
        if (index !== -1) {
            list[index] = {
                ...list[index],
                name: values.name,
                url: values.url,
                enabled: values.enabled,
            };
            updateClientFormField(field(), list);
        }
    };

    const openAddModal = () => {
        openModal(getAddModalId(props.whitelist ?? false));
    };

    const openEditModal = (url: string, name: string, enabled: boolean) => {
        setFilterToEdit({ url, name, enabled });
        openModal(getEditModalId(props.whitelist ?? false));
    };

    const handleRefresh = async () => {
        if (!props.clientName) {
            return;
        }
        await refreshFilters({ whitelist: props.whitelist ?? false, client: props.clientName });
        const detail = await clientDetail({ name: props.clientName });
        const refreshed = props.whitelist ? detail.whitelist_filters ?? [] : detail.filters ?? [];
        updateClientFormField({ field: field(), value: refreshed });
    };

    return (
        <div class={s.wrapper}>
            <div class={s.actions}>
                <PlusButton onClick={openAddModal} testId="client-filters-add">
                    {props.whitelist
                        ? intl.getMessage('add_allowlist')
                        : intl.getMessage('add_blocklist')}
                </PlusButton>

                <button
                    type="button"
                    onClick={handleRefresh}
                    disabled={!props.clientName || filters().length === 0}
                    class={cn(s.refreshButton, theme.text.t3)}
                >
                    <Icon icon="refresh" color="green" />
                    <span>{intl.getMessage('check_updates_btn')}</span>
                </button>
            </div>

            <ListsTable
                tableId={TABLE_IDS_BY_FIELD[field()]}
                filters={filters()}
                processingConfigFilter={false}
                toggleFilterList={handleToggle}
                addFilterList={openAddModal}
                editFilterList={openEditModal}
                deleteFilterList={handleDelete}
            />

            <Show when={props.whitelist}>
                <ClientFiltersModal
                    modalId={getAddModalId(true)}
                    whitelist
                    existingUrls={existingUrls()}
                    onAdd={handleAdd}
                    onEdit={handleEdit}
                />
                <ClientFiltersModal
                    modalId={getEditModalId(true)}
                    whitelist
                    filterToEdit={filterToEdit()}
                    existingUrls={existingUrls()}
                    onAdd={handleAdd}
                    onEdit={handleEdit}
                />
            </Show>
            <Show when={!props.whitelist}>
                <ClientFiltersModal
                    modalId={getAddModalId(false)}
                    whitelist={false}
                    existingUrls={existingUrls()}
                    onAdd={handleAdd}
                    onEdit={handleEdit}
                />
                <ClientFiltersModal
                    modalId={getEditModalId(false)}
                    whitelist={false}
                    filterToEdit={filterToEdit()}
                    existingUrls={existingUrls()}
                    onAdd={handleAdd}
                    onEdit={handleEdit}
                />
            </Show>
        </div>
    );
};

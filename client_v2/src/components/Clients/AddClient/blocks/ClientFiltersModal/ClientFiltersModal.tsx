import { createSignal, createMemo, createEffect, Show, untrack } from 'solid-js';

import intl from 'panel/common/intl';
import { Dialog } from 'panel/common/ui/Dialog/Dialog';
import { MODAL_TYPE, TAB_TYPE } from 'panel/helpers/constants';
import { ModalWrapper } from 'panel/common/ui/ModalWrapper';
import { closeModal } from 'panel/stores/modals';
import theme from 'panel/lib/theme';
import { Button } from 'panel/common/ui/Button';
import { Input } from 'panel/common/controls/Input';
import { validatePath, validateRequiredValue } from 'panel/helpers/validators';
import { ManualFilterForm } from 'panel/components/FilterLists/blocks/ConfigureBlocklistModal/blocks/ManualFilterForm';
import { FiltersList } from 'panel/components/FilterLists/blocks/ConfigureBlocklistModal/blocks/FiltersList';
import { Tabs } from 'panel/common/ui/Tabs';
import filtersCatalog from 'panel/helpers/filters/filters';

import s from './ClientFiltersModal.module.pcss';

type FormValues = {
    name: string;
    url: string;
    enabled?: boolean;
};

type Props = {
    modalId: string;
    whitelist: boolean;
    filterToEdit?: FormValues;
    existingUrls: string[];
    onAdd: (filters: Array<{ name: string; url: string }>) => void;
    onEdit: (currentUrl: string, values: { name: string; url: string; enabled: boolean }) => void;
};

const isEditModal = (modalId: string, whitelist: boolean) =>
    modalId === (whitelist ? MODAL_TYPE.EDIT_ALLOWLIST : MODAL_TYPE.EDIT_BLOCKLIST);

const getTitle = (modalId: string, whitelist: boolean) => {
    if (isEditModal(modalId, whitelist)) {
        return whitelist ? intl.getMessage('allowlist_edit') : intl.getMessage('blocklist_edit');
    }

    return whitelist ? intl.getMessage('allowlist_add') : intl.getMessage('blocklists_add');
};

const getButtonText = (modalId: string, whitelist: boolean) => {
    if (isEditModal(modalId, whitelist)) {
        return intl.getMessage('save');
    }

    return intl.getMessage('add');
};

export const ClientFiltersModal = (props: Props) => {
    const catalogSourcesToIdMap = createMemo(() => {
        const map: Record<string, string> = {};
        Object.entries(filtersCatalog.filters).forEach(([filterId, filterData]) => {
            map[filterData.source] = filterId;
        });
        return map;
    });

    const selectedValues = createMemo(() => {
        const selectedFilterIds: Record<string, boolean> = {};
        const selectedSources: Record<string, boolean> = {};
        props.existingUrls.forEach((url: string) => {
            if (Object.hasOwn(catalogSourcesToIdMap(), url)) {
                const filterId = catalogSourcesToIdMap()[url];
                selectedFilterIds[filterId] = true;
                selectedSources[url] = true;
            }
        });
        return { selectedFilterIds, selectedSources };
    });

    const [activeTab, setActiveTab] = createSignal(TAB_TYPE.LIST);
    const [selectedFilterIds, setSelectedFilterIds] = createSignal<Record<string, boolean>>({});
    const [name, setName] = createSignal(untrack(() => props.filterToEdit?.name) ?? '');
    const [url, setUrl] = createSignal(untrack(() => props.filterToEdit?.url) ?? '');
    const [urlError, setUrlError] = createSignal<string | undefined>();

    createEffect(() => {
        if (isEditModal(props.modalId, props.whitelist)) {
            setName(props.filterToEdit?.name ?? '');
            setUrl(props.filterToEdit?.url ?? '');
        } else {
            setSelectedFilterIds(selectedValues().selectedFilterIds);
        }
    });

    const validateAndSetErrors = () => {
        const urlErr = validateRequiredValue(url()) || validatePath(url());
        setUrlError(urlErr || undefined);
        return !urlErr;
    };

    const handleFormSubmit = (e: Event) => {
        e.preventDefault();

        if (isEditModal(props.modalId, props.whitelist)) {
            if (!props.filterToEdit || !validateAndSetErrors()) {
                return;
            }
            props.onEdit(props.filterToEdit.url, {
                name: name(),
                url: url(),
                enabled: props.filterToEdit.enabled ?? true,
            });
            closeModal();
            return;
        }

        const form = e.target as HTMLFormElement;
        const formData = new FormData(form);
        const values: FormValues = {
            name: (formData.get('name') as string) || '',
            url: (formData.get('url') as string) || '',
        };

        if (values.url && values.name) {
            const nameErr = validateRequiredValue(values.name);
            const urlErr = validateRequiredValue(values.url) || validatePath(values.url);
            if (nameErr || urlErr) {
                return;
            }
            props.onAdd([{ name: values.name, url: values.url }]);
        } else {
            const filtersToAdd = Object.entries(selectedFilterIds())
                .filter(([id, selected]) => selected && id in filtersCatalog.filters)
                .map(([id]) => {
                    const { source, name: filterName } =
                        filtersCatalog.filters[id as keyof typeof filtersCatalog.filters];
                    return { name: filterName, url: source };
                })
                .filter((filter) => !props.existingUrls.includes(filter.url));

            props.onAdd(filtersToAdd);
        }

        setSelectedFilterIds({});
        closeModal();
    };

    const handleCancel = () => {
        setName('');
        setUrl('');
        setUrlError(undefined);
        setSelectedFilterIds({});
        closeModal();
    };

    return (
        <ModalWrapper id={props.modalId}>
            <Dialog visible onClose={handleCancel} title={getTitle(props.modalId, props.whitelist)}>
                <form onSubmit={handleFormSubmit}>
                    <div>
                        <Show
                            when={!isEditModal(props.modalId, props.whitelist)}
                            fallback={
                                <div class={theme.form.group}>
                                    <div class={theme.form.input}>
                                        <Input
                                            type="text"
                                            id="filters_name"
                                            label={intl.getMessage('name_label')}
                                            placeholder={intl.getMessage('blocklist_placeholder_example')}
                                            value={name()}
                                            onChange={(e) =>
                                                setName((e.target as HTMLInputElement).value)
                                            }
                                        />
                                    </div>

                                    <div class={theme.form.input}>
                                        <Input
                                            type="text"
                                            id="filters_url"
                                            label={intl.getMessage('blocklist_url_file_path')}
                                            placeholder={intl.getMessage('blocklist_url_file_path')}
                                            value={url()}
                                            onChange={(e) =>
                                                setUrl((e.target as HTMLInputElement).value)
                                            }
                                            onBlur={validateAndSetErrors}
                                            errorMessage={urlError()}
                                        />
                                    </div>
                                </div>
                            }
                        >
                            <p class={s.desc}>{intl.getMessage('blocklists_add_desc')}</p>

                            <Tabs
                                activeTab={activeTab()}
                                onTabChange={setActiveTab}
                                contentClass={s.content}
                                tabs={[
                                    {
                                        id: TAB_TYPE.LIST,
                                        label: intl.getMessage('blocklist_add_from_list'),
                                        content: (
                                            <FiltersList
                                                selectedSources={selectedValues().selectedSources}
                                                selectedIds={selectedFilterIds()}
                                                onChange={setSelectedFilterIds}
                                            />
                                        ),
                                    },
                                    {
                                        id: TAB_TYPE.MANUAL,
                                        label: intl.getMessage('blocklist_add_manual'),
                                        content: (
                                            <ManualFilterForm class={s.formGroup} />
                                        ),
                                    },
                                ]}
                            />
                        </Show>
                    </div>

                    <div class={theme.dialog.footer}>
                        <Button
                            type="submit"
                            id="filters_save"
                            variant="primary"
                            size="small"
                            class={theme.dialog.button}
                        >
                            {getButtonText(props.modalId, props.whitelist)}
                        </Button>

                        <Button
                            type="button"
                            id="filters_cancel"
                            variant="secondary"
                            size="small"
                            onClick={handleCancel}
                            class={theme.dialog.button}
                        >
                            {intl.getMessage('cancel')}
                        </Button>
                    </div>
                </form>
            </Dialog>
        </ModalWrapper>
    );
};

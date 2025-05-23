import React, { useEffect, useMemo, useState } from 'react';
import { connect } from 'react-redux';
import { withTranslation } from 'react-i18next';
import { useFormContext } from 'react-hook-form';
import { toggleFilteringModal, refreshFilters } from '../../../actions/filtering';
import { normalizeFilters, getCurrentFilter, deNormalizeFilters, Filter } from '../../../helpers/helpers';
import Card from '../../ui/Card';
import Table from '../../Filters/Table';
import Modal from '../../Filters/Modal';
import Actions from '../../Filters/Actions';
import filtersCatalog from '../../../helpers/filters/filters';

import { MODAL_TYPE } from '../../../helpers/constants';
import { Client, FilteringData } from '../../../initialState';
import { ClientForm } from './Form/types';

interface FiltersTableProps {
    whitelist?: boolean;
    filters?: Filter[];
    whitelistFilters?: Filter[];
    t?: (key: string) => string;
    title: string;
    toggleFilteringModal?: (options?: any) => void;
    filtering?: FilteringData;
    refreshFilters?: (params?: any) => void;
    client?: string;
    clientDetail?: Client;
}

let FiltersTable = (props: FiltersTableProps) => {
    const {
        whitelist,
        t,
        title,
        toggleFilteringModal,
        client,
        filtering: {
            isModalOpen,
            isFilterAdded,
            processingRefreshFilters,
            processingRemoveFilter,
            processingAddFilter,
            processingConfigFilter,
            processingFilters,
            modalType,
            modalFilterUrl,
        },
        clientDetail,
    } = props;

    const { watch, setValue } = useFormContext<ClientForm>();

    const filtersKey = useMemo(() => (whitelist ? 'whitelist_filters' : 'filters'), [whitelist]);

    const filters = normalizeFilters(whitelist ? watch('whitelist_filters') : watch('filters'));

    useEffect(() => {
        if (clientDetail && clientDetail.name) {
            setValue(filtersKey, deNormalizeFilters(filters));
        }
    }, [clientDetail]);

    const loading =
        processingConfigFilter ||
        processingFilters ||
        processingAddFilter ||
        processingRemoveFilter ||
        processingRefreshFilters;

    const [filtersChanged, setFiltersChanged] = useState({
        whitelist_filters: false,
        filters: false,
    });

    const hideRefreshButton = useMemo(() => {
        return !client || !filters.length || filtersChanged[filtersKey];
    }, [client, filters, filtersChanged, filtersKey]);

    const onFiltersChange = () => {
        setValue(filtersKey, deNormalizeFilters(filters));
        const newFiltersChanged = { ...filtersChanged };
        newFiltersChanged[filtersKey] = true;
        setFiltersChanged(newFiltersChanged);
    };
    const deleteFilter = (url) => {
        const filterIndex = filters.findIndex((item) => item.url === url);
        if (filterIndex !== -1) {
            filters.splice(filterIndex, 1);
            onFiltersChange();
        }
    };
    const toggleFilter = (url) => {
        const filterIndex = filters.findIndex((item) => item.url === url);
        if (filterIndex !== -1) {
            filters[filterIndex].enabled = !filters[filterIndex].enabled;
            onFiltersChange();
        }
    };
    const openSelectTypeModal = () => {
        toggleFilteringModal({ type: MODAL_TYPE.SELECT_MODAL_TYPE });
    };
    const handleSubmitFilter = (values) => {
        toggleFilteringModal();
        switch (modalType) {
            case MODAL_TYPE.EDIT_FILTERS: {
                const filterIndex = filters.findIndex((item) => item.url === modalFilterUrl);
                if (filterIndex !== -1) {
                    filters[filterIndex].url = values.url;
                    filters[filterIndex].name = values.name;
                    onFiltersChange();
                }
                break;
            }
            case MODAL_TYPE.ADD_FILTERS: {
                filters.push({
                    enabled: true,
                    name: values.name,
                    url: values.url,
                });
                onFiltersChange();
                break;
            }
            case MODAL_TYPE.CHOOSE_FILTERING_LIST: {
                const changedValues = Object.entries(values)?.reduce((acc, [key, value]) => {
                    if (value && key in filtersCatalog.filters) {
                        acc[key] = value;
                    }
                    return acc;
                }, {});

                Object.keys(changedValues).forEach((fieldName) => {
                    // filterId is actually in the field name
                    const { source, name } = filtersCatalog.filters[fieldName];
                    filters.push({
                        enabled: true,
                        name,
                        url: source,
                    });
                });
                onFiltersChange();
                break;
            }
            default:
                break;
        }
    };
    const handleRefreshFilter = () => {
        props.refreshFilters({ whitelist: false, client });
    };
    const currentFilterData = getCurrentFilter(modalFilterUrl, filters);
    return (
        <>
            <div className="form__label--bot form__label--bold">{title}</div>
            <div className="row">
                <div className="col-md-12">
                    <Card subtitle={t('filters_and_hosts_hint')}>
                        <Table
                            filters={filters}
                            loading={loading}
                            whitelist={whitelist}
                            processingConfigFilter={processingConfigFilter}
                            toggleFilteringModal={toggleFilteringModal}
                            handleDelete={deleteFilter}
                            toggleFilter={toggleFilter}
                        />
                        <Actions
                            normalButton
                            hideRefresh={hideRefreshButton}
                            whitelist={whitelist}
                            handleAdd={openSelectTypeModal}
                            handleRefresh={handleRefreshFilter}
                            processingRefreshFilters={processingConfigFilter}
                        />
                    </Card>
                </div>
            </div>
            <Modal
                filters={filters}
                filtersCatalog={filtersCatalog}
                isOpen={isModalOpen}
                toggleFilteringModal={toggleFilteringModal}
                isFilterAdded={isFilterAdded}
                processingAddFilter={processingAddFilter}
                processingConfigFilter={processingConfigFilter}
                handleSubmit={handleSubmitFilter}
                modalType={modalType}
                currentFilterData={currentFilterData}
                whitelist={whitelist}
            />
        </>
    );
};

const mapStateToProps = (state) => {
    const {
        filtering,
        client: { clientDetail },
    } = state;
    return {
        filtering,
        clientDetail,
    };
};
const mapDispatchToProps = {
    toggleFilteringModal,
    refreshFilters,
};

FiltersTable = connect(
    mapStateToProps,
    mapDispatchToProps,
)(FiltersTable);

export default withTranslation()(FiltersTable);

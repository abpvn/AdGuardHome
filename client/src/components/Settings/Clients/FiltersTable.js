import React from 'react';
import { connect } from 'react-redux';
import {
    formValueSelector, change,
} from 'redux-form';
import PropTypes from 'prop-types';
import { withTranslation } from 'react-i18next';
import { toggleFilteringModal, refreshFilters } from '../../../actions/filtering';
import {
    normalizeFilters,
    getCurrentFilter,
} from '../../../helpers/helpers';
import Card from '../../ui/Card';
import Table from '../../Filters/Table';
import Modal from '../../Filters/Modal';
import Actions from '../../Filters/Actions';
import filtersCatalog from '../../../helpers/filters/filters';

import { FORM_NAME, MODAL_TYPE } from '../../../helpers/constants';

let FiltersTable = (props) => {
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
    } = props;
    const filters = whitelist ? props.whitelistFilters : props.filters;
    const loading = processingConfigFilter
            || processingFilters
            || processingAddFilter
            || processingRemoveFilter
            || processingRefreshFilters;
    const onFiltersChange = () => {
        props.change(FORM_NAME.CLIENT, whitelist ? 'whitelist_filters' : 'filters', filters);
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

                Object.keys(changedValues)
                    .forEach((fieldName) => {
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
    return (<>
        <div className="form__label--bot form__label--bold">
            {title}
        </div>
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
                        hideRefresh={!client}
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
            addFilter={() => {}}
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

FiltersTable.propTypes = {
    whitelist: PropTypes.bool,
    filters: PropTypes.array.isRequired,
    whitelistFilters: PropTypes.array.isRequired,
    t: PropTypes.func.isRequired,
    title: PropTypes.string.isRequired,
    toggleFilteringModal: PropTypes.func.isRequired,
    filtering: PropTypes.object.isRequired,
    change: PropTypes.func.isRequired,
    refreshFilters: PropTypes.func.isRequired,
    client: PropTypes.string,
};

const selector = formValueSelector(FORM_NAME.CLIENT);
const mapStateToProps = (state) => {
    const filters = normalizeFilters(selector(state, 'filters'));
    const whitelistFilters = normalizeFilters(selector(state, 'whitelist_filters'));
    const { filtering } = state;
    return {
        filters,
        whitelistFilters,
        filtering,
    };
};
const mapDispatchToProps = {
    toggleFilteringModal,
    change,
    refreshFilters,
};

FiltersTable = connect(
    mapStateToProps,
    mapDispatchToProps,
)(FiltersTable);

export default withTranslation()(FiltersTable);

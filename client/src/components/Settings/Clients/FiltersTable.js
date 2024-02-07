import React from 'react';
import { connect } from 'react-redux';
import {
    formValueSelector,
} from 'redux-form';
import PropTypes from 'prop-types';
import { withTranslation } from 'react-i18next';
import { toggleFilteringModal } from '../../../actions/filtering';
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
    const deleteFilter = (options) => {
        console.log(options);
    };
    const toggleFilter = (options) => {
        console.log(options);
    };
    const openSelectTypeModal = () => {
        toggleFilteringModal({ type: MODAL_TYPE.SELECT_MODAL_TYPE });
    };
    const addFilter = (options) => {
        console.log(options);
    };
    const handleSubmit = (values) => {
        toggleFilteringModal();
        console.log(values);
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
                        whitelist={whitelist}
                        handleAdd={openSelectTypeModal}
                        handleRefresh={() => { }}
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
            addFilter={addFilter}
            isFilterAdded={isFilterAdded}
            processingAddFilter={processingAddFilter}
            processingConfigFilter={processingConfigFilter}
            handleSubmit={handleSubmit}
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
};

FiltersTable = connect(
    mapStateToProps,
    mapDispatchToProps,
)(FiltersTable);

export default withTranslation()(FiltersTable);

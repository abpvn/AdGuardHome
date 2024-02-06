import React from 'react';
import { connect } from 'react-redux';
import {
    formValueSelector,
} from 'redux-form';
import PropTypes from 'prop-types';
import { withTranslation } from 'react-i18next';
import {
    normalizeFilters,
} from '../../../helpers/helpers';
import Card from '../../ui/Card';
import Table from '../../Filters/Table';
import Actions from '../../Filters/Actions';

import { FORM_NAME } from '../../../helpers/constants';

let FiltersTable = (props) => {
    const { whitelist, t, title } = props;
    const filters = whitelist ? props.whitelistFilters : props.filters;
    const toggleFilteringModal = (options) => {
        console.log(options);
    };
    const deleteFilter = (options) => {
        console.log(options);
    };
    const toggleFilter = (options) => {
        console.log(options);
    };
    return (<>
        <div className="form__label--bot form__label--bold">
            {title}
        </div>
        <div className="row">
            <div className="col-md-12">
                <Card subtitle={t('filters_and_hosts_hint')}>
                    <Table
                        filters={filters}
                        loading={false}
                        whitelist={whitelist}
                        processingConfigFilter={false}
                        toggleFilteringModal={toggleFilteringModal}
                        handleDelete={deleteFilter}
                        toggleFilter={toggleFilter}
                    />
                    <Actions
                        handleAdd={() => { }}
                        handleRefresh={() => { }}
                        processingRefreshFilters={false}
                    />
                </Card>
            </div>
        </div>
    </>
    );
};

FiltersTable.propTypes = {
    whitelist: PropTypes.bool,
    filters: PropTypes.array.isRequired,
    whitelistFilters: PropTypes.array.isRequired,
    t: PropTypes.func.isRequired,
    title: PropTypes.string.isRequired,
};

const selector = formValueSelector(FORM_NAME.CLIENT);

FiltersTable = connect((state) => {
    const filters = normalizeFilters(selector(state, 'filters'));
    const whitelistFilters = normalizeFilters(selector(state, 'whitelist_filters'));
    return {
        filters,
        whitelistFilters,
    };
})(FiltersTable);

export default withTranslation()(FiltersTable);

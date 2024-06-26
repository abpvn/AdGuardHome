import { createAction } from 'redux-actions';
import { addErrorToast } from './toasts';
import apiClient from '../api/Api';

export const getClientDetailRequest = createAction('GET_CLIENT_DETAIL_REQUEST');
export const getClientDetailFailure = createAction('GET_CLIENT_DETAIL_FAILURE');
export const getClientDetailSuccess = createAction('GET_CLIENT_DETAIL_SUCCESS');

export const getClientDetail = (name) => async (dispatch) => {
    dispatch(getClientDetailRequest());
    try {
        const data = await apiClient.getClientDetail(name);
        dispatch(getClientDetailSuccess({
            clientDetail: {
                name: data.name,
                whitelist_filters: data.whitelist_filters,
                filters: data.filters,
            },
        }));
    } catch (error) {
        dispatch(addErrorToast({ error }));
        dispatch(getClientDetailFailure());
    }
};

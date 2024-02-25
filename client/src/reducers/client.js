import { handleActions } from 'redux-actions';

import * as actions from '../actions/client';

const client = handleActions({
    [actions.getClientDetailRequest]: (state) => ({ ...state, isGettingClient: true }),
    [actions.getClientDetailFailure]: (state) => ({ ...state, isGettingClient: false }),
    [actions.getClientDetailSuccess]: (state, { payload }) => ({
        ...state,
        isGettingClient: false,
        clientDetail: payload.clientDetail,
    }),
}, {
    isGettingClient: false,
});

export default client;

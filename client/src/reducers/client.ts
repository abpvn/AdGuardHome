import { handleActions } from 'redux-actions';

import * as actions from '../actions/client';

const client = handleActions({
    [actions.getClientDetailRequest.toString()]: (state: any) => ({ ...state, isGettingClient: true }),
    [actions.getClientDetailFailure.toString()]: (state: any) => ({ ...state, isGettingClient: false }),
    [actions.getClientDetailSuccess.toString()]: (state: any, { payload }: any) => ({
        ...state,
        isGettingClient: false,
        clientDetail: payload.clientDetail,
    }),
}, {
    isGettingClient: false,
});

export default client;

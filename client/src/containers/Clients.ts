import { connect } from 'react-redux';

import { getClients } from '../actions';
import { getStats } from '../actions/stats';
import {
    addClient,
    updateClient,
    deleteClient,
    toggleClientModal,
    clearClientCache,
} from '../actions/clients';

import Clients from '../components/Settings/Clients';

const mapStateToProps = (state: any) => {
    const { dashboard, clients, stats } = state;
    const props = {
        dashboard,
        clients,
        stats,
    };
    return props;
};

type DispatchProps = {
    getClients: (dispatch: any) => void;
    getStats: (...args: unknown[]) => unknown;
    addClient: (dispatch: any) => void;
    updateClient: (config: any, name: any) => (dispatch: any) => void;
    deleteClient: (config: any, name: any) => (dispatch: any) => void;
    clearClientCache: (name: string) => (dispatch: any) => void;
    toggleClientModal: (...args: unknown[]) => unknown;
}

const mapDispatchToProps: DispatchProps = {
    getClients,
    getStats,
    addClient,
    updateClient,
    deleteClient,
    clearClientCache,
    toggleClientModal,
};

export default connect(mapStateToProps, mapDispatchToProps)(Clients);

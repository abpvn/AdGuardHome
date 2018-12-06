import { connect } from 'react-redux';
import * as actionCreators from '../actions';
import Login from '../components/Login';

const mapStateToProps = (state) => {
    const { dashboard } = state;
    const props = { dashboard };
    return props;
};

export default connect(
    mapStateToProps,
    actionCreators,
)(Login);

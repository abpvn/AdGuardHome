import { merge } from 'webpack-merge';
import yaml from 'js-yaml';
import fs from 'fs';
// eslint-disable-next-line import/extensions
import { BASE_URL } from './constants.js';
// eslint-disable-next-line import/extensions
import common from './webpack.common.js';

const ZERO_HOST = '0.0.0.0';
const LOCALHOST = '127.0.0.1';
const DEFAULT_PORT = 3000;

/**
 * Get document, or throw exception on error
 * @returns {{bind_host: string, bind_port: number}}
 */
const importConfig = () => {
    try {
        const doc = yaml.safeLoad(fs.readFileSync('../AdGuardHome.yaml', 'utf8'));
        const { http } = doc;
        const { address } = http;
        const splitAddress = address.split(':');
        const bind_host = splitAddress[0];
        const bind_port = parseInt(splitAddress[1], 10);
        return {
            bind_host,
            bind_port,
        };
    } catch (e) {
        console.error(e);
        return {
            bind_host: ZERO_HOST,
            bind_port: DEFAULT_PORT,
        };
    }
};

const getDevServerConfig = (proxyUrl = BASE_URL) => {
    const { bind_host: host, bind_port: port } = importConfig();
    const { DEV_SERVER_PORT } = process.env;

    const devServerHost = host === ZERO_HOST ? LOCALHOST : host;
    const devServerPort = DEV_SERVER_PORT || port + 8000;

    return {
        hot: true,
        open: true,
        host: devServerHost,
        port: devServerPort,
        proxy: [{
            context: [proxyUrl],
            target: `http://${devServerHost}:${port}`,
        }],
    };
};

export default merge(common, {
    devtool: 'eval-source-map',
    ...(process.env.WEBPACK_SERVE ? { devServer: getDevServerConfig(BASE_URL) } : undefined),
});

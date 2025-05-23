import React, { useEffect, useState } from 'react';
import { Trans } from 'react-i18next';

import Modal from 'react-modal';
import { shallowEqual, useDispatch, useSelector } from 'react-redux';

import { useHistory } from 'react-router-dom';
import queryString from 'query-string';
import classNames from 'classnames';
import { FormProvider, useForm } from 'react-hook-form';
import { BLOCK_ACTIONS, DEFAULT_LOGS_FILTER, MEDIUM_SCREEN_SIZE } from '../../helpers/constants';

import Loading from '../ui/Loading';

import Filters from './Filters';

import Disabled from './Disabled';
import { getFilteringStatus } from '../../actions/filtering';

import { getClients } from '../../actions';
import { getDnsConfig } from '../../actions/dnsConfig';
import { getAccessList } from '../../actions/access';
import { getAllBlockedServices } from '../../actions/services';
import { getLogsConfig, resetFilteredLogs, setFilteredLogs, toggleDetailedLogs } from '../../actions/queryLogs';

import InfiniteTable from './InfiniteTable';
import './Logs.css';
import { BUTTON_PREFIX } from './Cells/helpers';

import AnonymizerNotification from './AnonymizerNotification';
import { RootState } from '../../initialState';

export type SearchFormValues = {
    search: string;
    response_status: string;
    client: string;
};

const processContent = (data: any, _buttonType: string) =>
    Object.entries(data).map(([key, value]) => {
        if (!value) {
            return null;
        }

        const isTitle = value === 'title';
        const isButton = key.startsWith(BUTTON_PREFIX);
        const isBoolean = typeof value === 'boolean';
        const isHidden = isBoolean && value === false;

        let keyClass = 'key-colon';

        if (isTitle) {
            keyClass = 'title--border';
        }
        if (isButton || isBoolean) {
            keyClass = '';
        }

        return isHidden ? null : (
            <div className="grid__row" key={key}>
                <div
                    className={classNames(`key__${key}`, keyClass, {
                        'font-weight-bold': isBoolean && value === true,
                    })}>
                    <Trans>{isButton ? value : key}</Trans>
                </div>

                <div className={`value__${key} text-pre text-truncate`}>
                    <Trans>{isTitle || isButton || isBoolean ? '' : value || '—'}</Trans>
                </div>
            </div>
        );
    });

const Logs = () => {
    const dispatch = useDispatch();
    const history = useHistory();

    const {
        response_status: response_status_url_param,
        search: search_url_param,
        client: client_url_param,
    } = queryString.parse(history.location.search);

    const {
        enabled,
        processingGetConfig,
        processingGetLogs,
        anonymize_client_ip: anonymizeClientIp,
    } = useSelector((state: RootState) => state.queryLogs, shallowEqual);

    const filter = useSelector((state: RootState) => state.queryLogs.filter, shallowEqual);

    const logs = useSelector((state: RootState) => state.queryLogs.logs, shallowEqual);

    const search = search_url_param || filter?.search || '';
    const response_status = response_status_url_param || filter?.response_status || '';
    const client = client_url_param || filter?.client || '';

    const formMethods = useForm<SearchFormValues>({
        mode: 'onBlur',
        defaultValues: {
            search: search || DEFAULT_LOGS_FILTER.search,
            response_status: response_status || DEFAULT_LOGS_FILTER.response_status,
            client: client || DEFAULT_LOGS_FILTER.client,
        },
    });

    const { watch } = formMethods;
    const currentQuery = watch('search');

    const [isSmallScreen, setIsSmallScreen] = useState(window.innerWidth <= MEDIUM_SCREEN_SIZE);
    const [detailedDataCurrent, setDetailedDataCurrent] = useState({});
    const [buttonType, setButtonType] = useState(BLOCK_ACTIONS.BLOCK);
    const [isModalOpened, setModalOpened] = useState(false);
    const [isLoading, setIsLoading] = useState(false);

    const closeModal = () => setModalOpened(false);

    // Add effect to sync client_url_param changes to formMethods
    useEffect(() => {
        const { client: newClient } = queryString.parse(history.location.search);
        const currentClient = formMethods.getValues('client');
        if (newClient && newClient !== currentClient) {
            formMethods.setValue('client', newClient as string);
        } else if (!newClient && currentClient !== DEFAULT_LOGS_FILTER.client) {
            formMethods.setValue('client', DEFAULT_LOGS_FILTER.client);
        }
    }, [history.location.search]);

    useEffect(() => {
        (async () => {
            setIsLoading(true);
            await dispatch(
                setFilteredLogs({
                    search,
                    response_status,
                    client
                }),
            );
            setIsLoading(false);
        })();
    }, [response_status, search, client]);

    const mediaQuery = window.matchMedia(`(max-width: ${MEDIUM_SCREEN_SIZE}px)`);
    const mediaQueryHandler = (e: any) => {
        setIsSmallScreen(e.matches);
        if (e.matches) {
            dispatch(toggleDetailedLogs(false));
        } else {
            dispatch(toggleDetailedLogs(true));
        }
    };

    useEffect(() => {
        try {
            mediaQuery.addEventListener('change', mediaQueryHandler);
        } catch (e1) {
            try {
                // Safari 13.1 do not support mediaQuery.addEventListener('change', handler)
                mediaQuery.addListener(mediaQueryHandler);
            } catch (e2) {
                console.error(e2);
            }
        }

        (async () => {
            setIsLoading(true);
            dispatch(getFilteringStatus());
            dispatch(getClients());
            dispatch(getAllBlockedServices());
            try {
                await Promise.all([dispatch(getLogsConfig()), dispatch(getDnsConfig()), dispatch(getAccessList())]);
            } catch (err) {
                console.error(err);
            } finally {
                setIsLoading(false);
            }
        })();

        return () => {
            try {
                mediaQuery.removeEventListener('change', mediaQueryHandler);
            } catch (e1) {
                try {
                    // Safari 13.1 do not support mediaQuery.addEventListener('change', handler)
                    mediaQuery.removeListener(mediaQueryHandler);
                } catch (e2) {
                    console.error(e2);
                }
            }

            dispatch(resetFilteredLogs());
        };
    }, []);

    useEffect(() => {
        if (!history.location.search) {
            (async () => {
                setIsLoading(true);

                await dispatch(setFilteredLogs());
                setIsLoading(false);
            })();
        }
    }, [history.location.search]);

    const renderPage = () => (
        <>
            <FormProvider {...formMethods}>
                <Filters
                    setIsLoading={setIsLoading}
                    processingGetLogs={processingGetLogs}
                />
            </FormProvider>

            <InfiniteTable
                isLoading={isLoading}
                items={logs}
                isSmallScreen={isSmallScreen}
                setDetailedDataCurrent={setDetailedDataCurrent}
                setButtonType={setButtonType}
                setModalOpened={setModalOpened}
                currentQuery={currentQuery}
            />

            <Modal
                portalClassName="grid"
                isOpen={isSmallScreen && isModalOpened}
                onRequestClose={closeModal}
                style={{
                    content: {
                        width: 'calc(100% - 32px)',
                        height: 'fit-content',
                        left: '50%',
                        top: 47,
                        padding: '0',
                        maxWidth: '720px',
                        transform: 'translateX(-50%)',
                    },
                    overlay: {
                        backgroundColor: 'rgba(0,0,0,0.5)',
                    },
                }}>
                <div className="logs__modal-wrap">
                    <svg className="icon icon--24 icon-cross d-block cursor--pointer" onClick={closeModal}>
                        <use xlinkHref="#cross" />
                    </svg>

                    {processContent(detailedDataCurrent, buttonType)}
                </div>
            </Modal>
        </>
    );

    return (
        <>
            {enabled && (
                <>
                    {processingGetConfig && <Loading />}

                    {anonymizeClientIp && <AnonymizerNotification />}
                    {!processingGetConfig && renderPage()}
                </>
            )}

            {!enabled && !processingGetConfig && <Disabled />}
        </>
    );
};

export default Logs;

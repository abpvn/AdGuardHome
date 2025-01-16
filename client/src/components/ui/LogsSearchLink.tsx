import React from 'react';

import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { getLogsUrlParams } from '../../helpers/helpers';
import { MENU_URLS } from '../../helpers/constants';

interface LogsSearchLinkProps {
    children: string | number | React.ReactElement;
    search?: string;
    response_status?: string;
    link?: string;
    client?: string;
}

const LogsSearchLink = ({
    search = '',
    response_status = '',
    children,
    client,
    link = MENU_URLS.logs,
}: LogsSearchLinkProps) => {
    const { t } = useTranslation();

    const to =
        link === MENU_URLS.logs
            ? `${MENU_URLS.logs}${getLogsUrlParams(search && `"${search}"`, response_status, client)}`
            : link;

    return (
        <Link to={to} tabIndex={0} title={t('click_to_view_queries')} aria-label={t('click_to_view_queries')}>
            {children}
        </Link>
    );
};

export default LogsSearchLink;

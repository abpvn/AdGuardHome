import React from 'react';
import { withTranslation, Trans } from 'react-i18next';

interface ActionsProps {
    handleAdd: (...args: unknown[]) => unknown;
    handleRefresh: (...args: unknown[]) => unknown;
    processingRefreshFilters: boolean;
    whitelist?: boolean;
    normalButton?: boolean,
    hideRefresh?: boolean,
}

const Actions = ({
    handleAdd,
    handleRefresh,
    processingRefreshFilters,
    whitelist,
    normalButton,
    hideRefresh,
}: ActionsProps) => (
    <div className="card-actions">
        <button
            className="btn btn-success btn-standard mr-2 btn-large mb-2"
            type={normalButton ? 'button' : 'submit'}
            onClick={handleAdd}>
            {whitelist ? <Trans>add_allowlist</Trans> : <Trans>add_blocklist</Trans>}
        </button>

        {!hideRefresh && (
            <button
                className="btn btn-primary btn-standard mb-2"
                type={normalButton ? 'button' : 'submit'}
                onClick={handleRefresh}
                disabled={processingRefreshFilters}>
                <Trans>check_updates_btn</Trans>
            </button>
        )}
    </div>
);

export default withTranslation()(Actions);

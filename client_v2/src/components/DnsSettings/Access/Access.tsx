import { createMemo, Show } from 'solid-js';
import cn from 'clsx';

import { accessState, getAccessList } from 'panel/stores/access';
import intl from 'panel/common/intl';
import { SettingRow } from 'panel/common/ui/SettingRow';
import { useDialog } from 'panel/hooks/useDialog';
import { getListSummary } from '../helpers';
import theme from 'panel/lib/theme';

import { AllowedClientsDialog } from './blocks/AllowedClientsDialog';
import { DisallowedClientsDialog } from './blocks/DisallowedClientsDialog';
import { DisallowedDomainsDialog } from './blocks/DisallowedDomainsDialog';
import { AllowedCountriesDialog } from './blocks/AllowedCountriesDialog';
import { BlockedCountriesDialog } from './blocks/BlockedCountriesDialog';

export const Access = () => {
    const allowedDialog = useDialog();
    const disallowedClientsDialog = useDialog();
    const disallowedDomainsDialog = useDialog();
    const allowedCountriesDialog = useDialog();
    const blockedCountriesDialog = useDialog();

    const allowedClientsOn = createMemo(() => accessState.allowed_clients.trim().length > 0);
    const allowedCountriesOn = createMemo(() => accessState.allowed_countries.trim().length > 0);
    const processing = () => accessState.processingSet;

    const allowedClientsValue = createMemo(() => getListSummary(accessState.allowed_clients));
    const disallowedClientsValue = createMemo(() => getListSummary(accessState.disallowed_clients));
    const disallowedDomainsValue = createMemo(() => getListSummary(accessState.blocked_hosts));
    const allowedCountriesValue = createMemo(() => getListSummary(accessState.allowed_countries));
    const blockedCountriesValue = createMemo(() => getListSummary(accessState.blocked_countries));

    // A failed initial read still marks the store initialised, so seed the
    // editor from the server: saving an editor opened with empty lists would
    // replace the server's list with its contents.
    const openAccessDialog = async (openDialog: () => void) => {
        if (await getAccessList()) {
            openDialog();
        }
    };

    return (
        <div>
            <h2 class={cn(theme.layout.subtitle, theme.title.h5, theme.title.h4_tablet)}>
                {intl.getMessage('dns_access_settings_title')}
            </h2>

            <SettingRow
                variant="link"
                id="allowed_clients"
                title={intl.getMessage('dns_allowed_clients')}
                description={intl.getMessage('dns_allowed_clients_desc')}
                value={allowedClientsValue()}
                disabled={accessState.processing}
                onClick={() => void openAccessDialog(allowedDialog.openDialog)}
            />

            <SettingRow
                variant="link"
                id="disallowed_clients"
                title={intl.getMessage('dns_disallowed_clients')}
                description={
                    <>
                        <p>{intl.getMessage('dns_disallowed_clients_desc')}</p>
                        <Show when={allowedClientsOn()}>
                            <p class={theme.status.statusYellow}>
                                {intl.getMessage('dns_disallowed_clients_notice')}
                            </p>
                        </Show>
                    </>
                }
                value={disallowedClientsValue()}
                disabled={accessState.processing || allowedClientsOn()}
                onClick={() => void openAccessDialog(disallowedClientsDialog.openDialog)}
            />

            <SettingRow
                variant="link"
                id="allowed_countries"
                title={intl.getMessage('dns_allowed_countries')}
                description={intl.getMessage('dns_allowed_countries_desc')}
                value={allowedCountriesValue()}
                onClick={allowedCountriesDialog.openDialog}
            />

            <SettingRow
                variant="link"
                id="blocked_countries"
                title={intl.getMessage('dns_blocked_countries')}
                description={intl.getMessage('dns_blocked_countries_desc')}
                value={blockedCountriesValue()}
                disabled={allowedCountriesOn()}
                onClick={blockedCountriesDialog.openDialog}
            />

            <SettingRow
                variant="link"
                id="disallowed_domains"
                title={intl.getMessage('dns_disallowed_domains')}
                description={intl.getMessage('dns_disallowed_domains_desc')}
                value={disallowedDomainsValue()}
                disabled={accessState.processing}
                onClick={() => void openAccessDialog(disallowedDomainsDialog.openDialog)}
            />

            <AllowedClientsDialog
                open={allowedDialog.open}
                onClose={allowedDialog.closeDialog}
                processing={processing()}
            />

            <DisallowedClientsDialog
                open={disallowedClientsDialog.open}
                onClose={disallowedClientsDialog.closeDialog}
                processing={processing()}
            />

            <AllowedCountriesDialog
                open={allowedCountriesDialog.open}
                onClose={allowedCountriesDialog.closeDialog}
                processing={processing()}
            />

            <BlockedCountriesDialog
                open={blockedCountriesDialog.open}
                onClose={blockedCountriesDialog.closeDialog}
                processing={processing()}
            />

            <DisallowedDomainsDialog
                open={disallowedDomainsDialog.open}
                onClose={disallowedDomainsDialog.closeDialog}
                processing={processing()}
            />
        </div>
    );
};

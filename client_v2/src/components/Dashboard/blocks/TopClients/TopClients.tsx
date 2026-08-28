import { Show, For, createSignal, createMemo, onCleanup } from 'solid-js';
import { useIsDesktop } from 'panel/helpers/useMediaQuery';

import intl from 'panel/common/intl';
import { Icon } from 'panel/common/ui/Icon';
import { Tooltip } from 'panel/common/ui/Tooltip';
import { QueriesTooltip } from 'panel/common/ui/QueriesTooltip';
import { Dropdown } from 'panel/common/ui/Dropdown';
import { ConfirmDialog } from 'panel/common/ui/ConfirmDialog';
import { Link } from 'panel/common/ui/Link';
import { RoutePath } from 'panel/components/Routes/Paths';
import { formatCompactNumber } from 'panel/helpers/helpers';
import { addErrorToast } from 'panel/stores/toasts';
import { accessState, toggleClientBlock } from 'panel/stores/access';
import theme from 'panel/lib/theme';
import cn from 'clsx';
import { useSortedData, TOP_CLIENTS_VISIBLE_ITEMS } from '../../hooks/useSortedData';
import { TableHeader } from '../TableHeader';
import { EmptyState } from '../EmptyState';
import { ClientTooltip } from '../ClientTooltip';

import s from './TopClients.module.pcss';

import type { ClientFindSubEntry } from 'panel/api/model/clientFindSubEntry';

type ClientInfo = {
    name: string;
    count: number;
    info?: ClientFindSubEntry;
};

type Props = {
    topClients: ClientInfo[];
    numDnsQueries: number;
    processingClientInfo?: boolean;
};

export const TopClients = (props: Props) => {
    let isMounted = true;
    onCleanup(() => {
        isMounted = false;
    });

    const disallowedClientsList = createMemo(() => {
        const str = accessState.disallowed_clients || '';
        return str ? str.split('\n').filter(Boolean) : [];
    });

    const [confirmDialog, setConfirmDialog] = createSignal<{
        open: boolean;
        client: string;
        action: 'block' | 'unblock';
        rule: string;
    }>({ open: false, client: '', action: 'block', rule: '' });
    const [openMenuClient, setOpenMenuClient] = createSignal<string | null>(null);

    const isDesktop = useIsDesktop();
    const { sortedData: sortedClients } = useSortedData(
        () => props.topClients,
        TOP_CLIENTS_VISIBLE_ITEMS,
    );

    const isClientBlocked = (client: ClientInfo) =>
        !!client.info?.disallowed || disallowedClientsList().includes(client.name);

    const handleBlockClient = async (clientIp: string) => {
        const disallowedList = accessState.disallowed_clients
            ? accessState.disallowed_clients.split('\n').filter(Boolean)
            : [];
        const isDisallowed = disallowedList.includes(clientIp);
        if (isDisallowed) {
            addErrorToast({
                error: new Error(intl.getMessage('client_already_blocked', { ip: clientIp })),
            });
            if (isMounted) {
                setConfirmDialog({ open: false, client: '', action: 'block', rule: '' });
            }
            return;
        }
        await toggleClientBlock(clientIp, false, '');
        if (isMounted) {
            setConfirmDialog({ open: false, client: '', action: 'block', rule: '' });
        }
    };

    const handleUnblockClient = async (clientIp: string, disallowedRule: string) => {
        await toggleClientBlock(clientIp, true, disallowedRule || clientIp);
        if (isMounted) {
            setConfirmDialog({ open: false, client: '', action: 'unblock', rule: '' });
        }
    };

    const openConfirmDialog = (client: ClientInfo, action: 'block' | 'unblock') => {
        setOpenMenuClient(null);
        setConfirmDialog({
            open: true,
            client: client.name,
            action,
            rule: client.info?.disallowed_rule || '',
        });
    };

    const getClientMenu = (client: ClientInfo) => {
        const isBlocked = isClientBlocked(client);

        return (
            <div class={s.protectionMenu}>
                <Show
                    when={isBlocked}
                    fallback={
                        <div
                            class={cn(
                                theme.text.t2,
                                theme.text.condenced,
                                s.protectionMenuItem,
                                s.protectionMenuItemRed,
                            )}
                            onClick={() => openConfirmDialog(client, 'block')}
                        >
                            {intl.getMessage('block_client')}
                        </div>
                    }
                >
                    <div
                        class={cn(
                            theme.text.t2,
                            theme.text.condenced,
                            theme.dropdown.item,
                            s.protectionMenuItem,
                        )}
                        onClick={() => openConfirmDialog(client, 'unblock')}
                    >
                        {intl.getMessage('unblock_client')}
                    </div>
                </Show>
            </div>
        );
    };

    const hasStats = createMemo(() => props.topClients.length > 0);

    return (
        <div class={s.card}>
            <div class={s.cardHeader}>
                <div class={cn(theme.title.h5, s.cardTitle)}>{intl.getMessage('top_clients')}</div>
            </div>

            <Show when={hasStats()}>
                <TableHeader
                    nameLabel={intl.getMessage('table_client')}
                    countLabel={intl.getMessage('queries')}
                />
            </Show>

            <div class={s.tableRows}>
                <Show when={hasStats()} fallback={<EmptyState />}>
                    <For each={sortedClients()}>
                        {(client) => {
                            const percent = createMemo(() =>
                                props.numDnsQueries > 0
                                    ? (client.count / props.numDnsQueries) * 100
                                    : 0,
                            );
                            const isBlocked = isClientBlocked(client);

                            return (
                                <div class={s.clientRow} data-testid="top-client-row">
                                    <div class={s.clientInfo}>
                                        <Link
                                            to={RoutePath.QueryLog}
                                            query={{ search: `"${client.name}"` }}
                                            class={cn(
                                                theme.text.t3,
                                                theme.text.condenced,
                                                s.clientIp,
                                                s.clientIpLink,
                                            )}
                                        >
                                            <Tooltip
                                                position="bottomLeft"
                                                content={
                                                    <ClientTooltip
                                                        address={client.name}
                                                        whoisInfo={client.info?.whois_info}
                                                        blocked={isBlocked}
                                                    />
                                                }
                                                class={theme.common.noShrink}
                                            >
                                                <Show
                                                    when={isBlocked}
                                                    fallback={
                                                        <Icon icon="wifi" class={s.tableRowIcon} />
                                                    }
                                                >
                                                    <Icon
                                                        icon="wifi_protect"
                                                        class={cn(
                                                            s.tableRowIcon,
                                                            s.tableRowIconDanger,
                                                        )}
                                                    />
                                                </Show>
                                            </Tooltip>

                                            {client.name}
                                        </Link>
                                    </div>

                                    <div class={s.tableRowRight}>
                                        <Show when={isDesktop()}>
                                            <div class={s.dropdowWrapper}>
                                                <QueriesTooltip count={client.count}>
                                                    <div
                                                        class={cn(
                                                            theme.text.t3,
                                                            theme.text.condenced,
                                                            s.queryCount,
                                                        )}
                                                    >
                                                        <Link
                                                            to={RoutePath.QueryLog}
                                                            query={{ search: `"${client.name}"` }}
                                                            class={cn(
                                                                theme.text.t3,
                                                                theme.text.condenced,
                                                                s.queryCountLink,
                                                            )}
                                                        >
                                                            {formatCompactNumber(client.count)}
                                                        </Link>

                                                        <div
                                                            class={cn(
                                                                theme.text.t3,
                                                                theme.text.condenced,
                                                                s.queryPercent,
                                                            )}
                                                        >
                                                            ({percent().toFixed(1)}%)
                                                        </div>
                                                    </div>
                                                </QueriesTooltip>
                                            </div>
                                        </Show>

                                        <Show when={isDesktop()}>
                                            <div class={s.queryBar}>
                                                <div
                                                    class={s.queryBarFill}
                                                    style={{ width: `${percent()}%` }}
                                                />
                                            </div>
                                        </Show>

                                        <div class={s.dropdownWrapper}>
                                            <Dropdown
                                                wrapClass={s.clientActionsDropdown}
                                                menu={getClientMenu(client)}
                                                position="bottomRight"
                                                noIcon
                                                open={openMenuClient() === client.name}
                                                onOpenChange={(isOpen: boolean) =>
                                                    setOpenMenuClient(isOpen ? client.name : null)
                                                }
                                            >
                                                <button type="button" class={s.actionButton}>
                                                    <Icon icon="bullets" />
                                                </button>
                                            </Dropdown>
                                        </div>
                                    </div>

                                    <div class={s.tableRowInfo}>
                                        <Show
                                            when={props.processingClientInfo}
                                            fallback={
                                                <div
                                                    data-testid="top-client-name"
                                                    class={cn(
                                                        theme.text.t4,
                                                        theme.text.condenced,
                                                        s.clientName,
                                                    )}
                                                >
                                                    {client.info?.name ||
                                                        intl.getMessage('not_available')}
                                                </div>
                                            }
                                        >
                                            <div
                                                class={s.clientInfoSkeleton}
                                                data-testid="client-info-skeleton"
                                            />
                                        </Show>
                                        <div class={s.tableRowQueriesInfo}>
                                            <div
                                                class={cn(
                                                    theme.text.t3,
                                                    theme.text.condenced,
                                                    s.queryCount,
                                                )}
                                            >
                                                <Link
                                                    to={RoutePath.QueryLog}
                                                    query={{ search: `"${client.name}"` }}
                                                    class={cn(
                                                        theme.text.t3,
                                                        theme.text.condenced,
                                                        s.queryCountLink,
                                                    )}
                                                >
                                                    {formatCompactNumber(client.count)}
                                                </Link>

                                                <div
                                                    class={cn(
                                                        theme.text.t3,
                                                        theme.text.condenced,
                                                        s.queryPercent,
                                                    )}
                                                >
                                                    ({percent().toFixed(1)}%)
                                                </div>
                                            </div>

                                            <div class={s.queryBar}>
                                                <div
                                                    class={s.queryBarFill}
                                                    style={{ width: `${percent()}%` }}
                                                />
                                            </div>
                                        </div>

                                        <div class={s.tableRowActions}>{getClientMenu(client)}</div>
                                    </div>
                                </div>
                            );
                        }}
                    </For>
                </Show>

                <Show when={confirmDialog().open}>
                    {(() => {
                        const dialog = confirmDialog();
                        const isBlock = dialog.action === 'block';
                        const country = dialog.rule.startsWith('COUNTRY:')
                            ? dialog.rule.split(':')[1]
                            : '';

                        return (
                            <ConfirmDialog
                                onClose={() =>
                                    setConfirmDialog({
                                        open: false,
                                        client: '',
                                        action: 'block',
                                        rule: '',
                                    })
                                }
                                title={
                                    isBlock
                                        ? intl.getMessage('confirm_client_block_title', {
                                              ip: dialog.client,
                                          })
                                        : intl.getMessage('confirm_client_unblock_title', {
                                              ip: dialog.client,
                                          })
                                }
                                text={
                                    isBlock
                                        ? intl.getMessage('confirm_client_block_desc', {
                                              ip: dialog.client,
                                          })
                                        : country
                                          ? intl.getMessage('client_confirm_unblock_country', {
                                                country,
                                            })
                                          : intl.getMessage('confirm_client_unblock_desc', {
                                                ip: dialog.client,
                                            })
                                }
                                buttonText={
                                    isBlock ? intl.getMessage('block') : intl.getMessage('unblock')
                                }
                                cancelText={intl.getMessage('cancel')}
                                buttonVariant={isBlock ? 'danger' : 'primary'}
                                onConfirm={() => {
                                    if (isBlock) {
                                        handleBlockClient(dialog.client);
                                    } else {
                                        handleUnblockClient(dialog.client, dialog.rule);
                                    }
                                }}
                            />
                        );
                    })()}
                </Show>
            </div>
        </div>
    );
};

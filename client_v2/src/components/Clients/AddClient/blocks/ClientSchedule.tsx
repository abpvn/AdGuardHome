import { createMemo } from 'solid-js';
import { useParams } from '@solidjs/router';
import cn from 'clsx';
import intl from 'panel/common/intl';
import { clientFormState } from 'panel/stores/clientForm';
import { useInitClientFormFromRoute } from 'panel/hooks/useInitClientFormFromRoute';
import { RoutePath, type RoutePathKey } from 'panel/components/Routes/Paths';
import theme from 'panel/lib/theme';
import { InactivitySchedule } from 'panel/components/BlockedServices/InactivitySchedule/InactivitySchedule';
import s from './ClientSchedule.module.pcss';

import { ClientsHeader } from './ClientsHeader';

export const ClientSchedule = () => {
    useInitClientFormFromRoute();
    let params: { clientName?: string };
    try {
        params = useParams<{ clientName?: string }>();
    } catch {
        params = {};
    }

    const routeClientName = createMemo(() =>
        params.clientName ? decodeURIComponent(params.clientName) : '',
    );
    const editClientName = createMemo(
        () => clientFormState.originalName || routeClientName(),
    );
    const isEdit = createMemo(() => clientFormState.mode === 'edit' || !!routeClientName());

    const blockedServicesPath = createMemo<RoutePathKey>(() =>
        isEdit() ? RoutePath.ClientsEditBlockedServices : RoutePath.ClientsBlockedServices,
    );

    return (
        <div class={cn(theme.layout.container, s.containerOverride)}>
            <ClientsHeader
                currentTitle={intl.getMessage('inactivity_schedule')}
                extraLinks={[
                    {
                        path: blockedServicesPath(),
                        title: intl.getMessage('blocked_services'),
                        props: isEdit()
                            ? { clientName: encodeURIComponent(editClientName()) }
                            : undefined,
                    },
                ]}
            />
            <div class={cn(theme.layout.containerIn, theme.layout.containerIn_one_col)}>
                <InactivitySchedule clientScope />
            </div>
        </div>
    );
};

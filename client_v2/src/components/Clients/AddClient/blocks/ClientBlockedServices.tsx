import { createMemo } from 'solid-js';
import { useParams } from '@solidjs/router';
import intl from 'panel/common/intl';
import { clientFormState } from 'panel/stores/clientForm';
import { useInitClientFormFromRoute } from 'panel/hooks/useInitClientFormFromRoute';
import { RoutePath } from 'panel/components/Routes/Paths';

import { BlockedServices } from 'panel/components/BlockedServices/BlockedServices';

import s from './ClientBlockedServices.module.pcss';

export const ClientBlockedServices = () => {
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

    const clientPageLink = createMemo(() =>
        isEdit()
            ? {
                  path: RoutePath.ClientsEdit,
                  title: editClientName() || intl.getMessage('clients_edit'),
                  props: { clientName: encodeURIComponent(editClientName()) },
              }
            : {
                  path: RoutePath.ClientsAdd,
                  title: intl.getMessage('clients_add'),
              },
    );

    const breadcrumbs = createMemo(() => ({
        parentLinks: [
            { path: RoutePath.Clients, title: intl.getMessage('client_settings') },
            clientPageLink(),
        ],
        currentTitle: intl.getMessage('blocked_services'),
    }));

    return <BlockedServices clientScope breadcrumbs={breadcrumbs()} class={s.containerOverride} />;
};

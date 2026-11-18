import { createMemo } from 'solid-js';
import { useMatch, useParams } from '@solidjs/router';
import cn from 'clsx';
import intl from 'panel/common/intl';
import { Breadcrumbs } from 'panel/common/ui/Breadcrumbs';
import { clientFormState } from 'panel/stores/clientForm';
import { Paths, RoutePath, type RoutePathKey } from 'panel/components/Routes/Paths';
import theme from 'panel/lib/theme';

import s from './ClientsHeader.module.pcss';

type ClientsHeaderProps = {
    currentTitle: string;
    extraLinks?: {
        path: RoutePathKey;
        title: string;
        props?: Partial<Record<string, string | number>>;
    }[];
};

export const ClientsHeader = (props: ClientsHeaderProps) => {
    let params: { clientName?: string };
    try {
        params = useParams<{ clientName?: string }>();
    } catch {
        params = {};
    }
    const extraLinks = () => props.extraLinks || [];

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

    const isAddMatch = useMatch(() => Paths.ClientsAdd);
    const isEditMatch = useMatch(() => Paths.ClientsEdit);
    const isMainFormPage = createMemo(
        () => isAddMatch() !== undefined || isEditMatch() !== undefined,
    );

    const pageTitle = createMemo(() =>
        isEdit() && isMainFormPage() ? intl.getMessage('clients_edit') : props.currentTitle,
    );

    const breadcrumbCurrent = createMemo(() =>
        isEdit() && isMainFormPage() ? editClientName() : pageTitle(),
    );

    const parentLinks = createMemo(() => [
        { path: RoutePath.Clients, title: intl.getMessage('client_settings') },
        ...(!isMainFormPage() ? [clientPageLink()] : []),
        ...extraLinks(),
    ]);

    return (
        <div class={s.headerWrapper}>
            <Breadcrumbs parentLinks={parentLinks()} currentTitle={breadcrumbCurrent()} />
            <h1
                class={cn(
                    theme.title.h4,
                    theme.title.h3_tablet,
                    theme.common.textOverflow,
                    s.title,
                )}
                title={pageTitle()}
            >
                {pageTitle()}
            </h1>
        </div>
    );
};

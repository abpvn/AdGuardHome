import { createMemo, Show } from 'solid-js';
import cn from 'clsx';

import intl from 'panel/common/intl';
import theme from 'panel/lib/theme';
import { PageLoader } from 'panel/common/ui/Loader';
import { clientFormState } from 'panel/stores/clientForm';
import { useInitClientFormFromRoute } from 'panel/hooks/useInitClientFormFromRoute';

import { ClientsHeader } from '../ClientsHeader';
import { ClientFiltersTable } from '../ClientFiltersTable';

import s from './DnsBlocklists.module.pcss';

export const DnsBlocklists = () => {
    const isReady = useInitClientFormFromRoute();
    const clientName = createMemo(() => clientFormState.name || clientFormState.originalName);

    return (
        <div class={cn(theme.layout.container, s.containerOverride)}>
            <div class={cn(theme.layout.containerIn, theme.layout.containerIn_one_col)}>
                <ClientsHeader currentTitle={intl.getMessage('dns_blocklists')} />

                <Show when={isReady()} fallback={<PageLoader />}>
                    <Show
                        when={!clientFormState.use_global_filters}
                        fallback={
                            <div class={s.useGlobalFilters}>
                                {intl.getMessage('use_global_filters')}
                            </div>
                        }
                    >
                        <ClientFiltersTable
                            title={intl.getMessage('dns_blocklists')}
                            clientName={clientName()}
                        />
                    </Show>
                </Show>
            </div>
        </div>
    );
};

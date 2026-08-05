import type { JSX } from 'solid-js';
import { A } from '@solidjs/router';
import cn from 'clsx';

import intl from 'panel/common/intl';
import theme from 'panel/lib/theme';
import { Paths, RoutePath } from 'panel/components/Routes/Paths';
import { getLogsUrlParams } from 'panel/helpers/helpers';

type Props = {
    children?: JSX.Element;
    search?: string;
    status?: string;
    reason?: string;
    client?: string;
    class?: string;
    stop?: boolean;
};

export const LogsSearchLink = (props: Props) => {
    const title = intl.getMessage('click_to_view_queries');

    const href = () =>
        `${Paths[RoutePath.QueryLogByClient]}${getLogsUrlParams(
            props.search || '',
            props.status || '',
            props.reason || '',
            props.client,
        )}`;

    const handleClick = (e: MouseEvent) => {
        if (props.stop) {
            e.stopPropagation();
        }
    };

    return (
        <A
            href={href()}
            title={title}
            aria-label={title}
            tabIndex={0}
            class={cn(theme.link.link, props.class)}
            onClick={handleClick}
        >
            {props.children}
        </A>
    );
};

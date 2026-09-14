import { Show } from 'solid-js';
import cn from 'clsx';

import theme from 'panel/lib/theme';

import type { WhoisInfo } from 'panel/initialState';

import s from './Whois.module.pcss';

type Props = {
    info?: WhoisInfo;
};

export const Whois = (props: Props) => {
    const country = () => props.info?.country || '';
    const city = () => props.info?.city || '';
    const org = () => props.info?.orgname || props.info?.org || '';

    const location = () => [country(), city()].filter(Boolean).join(',');
    const value = () => [location(), org()].filter(Boolean).join(' | ');

    return (
        <Show when={value()}>
            <div
                class={cn(theme.text.t4, theme.text.condenced, s.whois)}
                data-testid="top-client-whois"
            >
                {value()}
            </div>
        </Show>
    );
};
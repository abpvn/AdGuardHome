import { Show } from 'solid-js';
import intl from 'panel/common/intl';
import { StatusBlock } from './StatusBlock';

import s from './styles.module.pcss';

type Props = {
    validKey: boolean;
    keyType?: string;
};

export const KeyStatus = (props: Props) => (
    <StatusBlock
        variant={props.validKey ? 'success' : 'error'}
        title={
            props.validKey
                ? intl.getMessage('encryption_key_valid')
                : intl.getMessage('encryption_key_invalid')
        }
    >
            {/* The store keeps a stale `key_type` when a key fails to parse,
                so an invalid key must not leak the previous algorithm. */}
            <Show when={props.validKey && props.keyType}>
                <div class={s.statusText}>
                    {intl.getMessage('encryption_key_type', { value: props.keyType })}
                </div>
            </Show>
    </StatusBlock>
);

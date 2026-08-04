import { Show } from 'solid-js';
import cn from 'clsx';

import intl from 'panel/common/intl';
import theme from 'panel/lib/theme';
import { Textarea } from 'panel/common/controls/Textarea';
import { COMMENT_LINE_TOKENS } from 'panel/helpers/constants';
import { clientFormState, updateClientFormField } from 'panel/stores/clientForm';
import { Examples } from 'panel/components/UserRules/blocks/Examples';

import { ClientsHeader } from '../ClientsHeader';

import s from './CustomRules.module.pcss';

export const CustomRules = () => {
    const handleChange = (e: Event) => {
        updateClientFormField({
            field: 'user_rules',
            value: (e.target as HTMLTextAreaElement).value,
        });
    };

    return (
        <div class={cn(theme.layout.container, s.containerOverride)}>
            <div class={cn(theme.layout.containerIn, theme.layout.containerIn_one_col)}>
                <ClientsHeader currentTitle={intl.getMessage('custom_filtering_rules')} />

                <Show
                    when={!clientFormState.use_global_filters}
                    fallback={
                        <div class={s.useGlobalFilters}>{intl.getMessage('use_global_filters')}</div>
                    }
                >
                    <div class={s.section}>
                        <Textarea
                            id="client-user-rules"
                            value={clientFormState.user_rules}
                            onChange={handleChange}
                            placeholder={`# ${intl.getMessage('user_rules_placeholder')}\n\n@@||example.org`}
                            label={intl.getMessage('user_rules_desc')}
                            rows={12}
                            size="large"
                            highlightComments
                            commentPrefixes={COMMENT_LINE_TOKENS}
                        />
                    </div>

                    <Examples />
                </Show>
            </div>
        </div>
    );
};

import { untrack, type Accessor } from 'solid-js';

import { accessState, setAccessList } from 'panel/stores/access';
import intl from 'panel/common/intl';
import { ConfigDialog } from 'panel/common/ui/ConfigDialog';
import { Textarea } from 'panel/common/controls/Textarea';
import { useField } from 'panel/hooks/useField';
import theme from 'panel/lib/theme';

type Props = {
    open: Accessor<boolean>;
    onClose: () => void;
    processing: boolean;
};

export const BlockedCountriesDialog = (props: Props) => {
    const field = useField<string>(
        () => props.open(),
        () => accessState.blocked_countries,
    );

    return (
        <ConfigDialog
            open={props.open()}
            title={intl.getMessage('dns_blocked_countries')}
            description={<p>{intl.getMessage('dns_blocked_countries_desc')}</p>}
            onClose={props.onClose}
            onSubmit={() => {
                field.submitIfValid((v) => {
                    setAccessList({ blocked_countries: v });
                    untrack(() => props.onClose());
                });
            }}
            processing={props.processing}
        >
            <div class={theme.form.input}>
                <Textarea
                    value={field.value()}
                    onChange={(e: Event) => field.setValue((e.target as HTMLTextAreaElement).value)}
                    onBlur={() => {
                        field.setValue(field.value().toUpperCase());
                        field.validate();
                    }}
                    id="blocked_countries"
                    label={intl.getMessage('dns_blocked_countries_label')}
                    placeholder={intl.getMessage('example_countries_placeholder')}
                    size="medium"
                    errorMessage={field.error()}
                />
            </div>
        </ConfigDialog>
    );
};

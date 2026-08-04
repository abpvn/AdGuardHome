import { createEffect, createSignal } from 'solid-js';

import { SettingRow } from 'panel/common/ui/SettingRow';
import intl from 'panel/common/intl';
import { encryptionState, setTlsConfig } from 'panel/stores/encryption';

export const InsecureToggle = () => {
    const [localChecked, setLocalChecked] = createSignal(encryptionState.insecure_enabled, {
        equals: false,
    });
    const enc = () => encryptionState;

    createEffect(() => {
        if (!enc().processingConfig) {
            setLocalChecked(enc().insecure_enabled);
        }
    });

    const onChange = (checked: boolean) => {
        setTlsConfig({ insecure_enabled: checked });
    };

    return (
        <SettingRow
            id="insecure_enabled"
            variant="switch"
            title={intl.getMessage('encryption_insecure_enabled_enable')}
            description={intl.getMessage('insecure_enabled_desc')}
            checked={localChecked()}
            disabled={enc().processingConfig}
            onChange={onChange}
        />
    );
};

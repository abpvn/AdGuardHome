import { SettingRow } from 'panel/common/ui/SettingRow';
import intl from 'panel/common/intl';
import { encryptionState } from 'panel/stores/encryption';
import s from '../styles.module.pcss';

type Props = {
    onOpen: () => void;
};

export const ServerSettingsRow = (props: Props) => {
    const hasCert = () => !!(encryptionState.certificate_chain || encryptionState.certificate_path);
    const hasKey = () =>
        !!(
            encryptionState.private_key ||
            encryptionState.private_key_path ||
            encryptionState.private_key_saved
        );
    const isEnabled = () => hasCert() && hasKey();

    const serverNames = () =>
        (encryptionState.server_names || []).filter((name: string) => !!name);
    const serverName = () =>
        serverNames().length > 0 ? serverNames()[0] : intl.getMessage('none_text');
    const httpsPort = () => encryptionState.port_https || intl.getMessage('none_text');
    const dotPort = () => encryptionState.port_dns_over_tls || intl.getMessage('none_text');
    const doqPort = () => encryptionState.port_dns_over_quic || intl.getMessage('none_text');

    const serverNameSummary = () =>
        serverNames().length > 1
            ? intl.getMessage('encryption_server_summary_multi', {
                  value: serverNames()[0],
                  count: serverNames().length,
              })
            : intl.getMessage('encryption_server_summary', { value: serverName() });

    return (
        <SettingRow
            id="encrypted_dns_settings"
            variant="link"
            title={intl.getMessage('encrypted_dns_settings')}
            description={
                <>
                    <div class={s.summaryLine}>{serverNameSummary()}</div>
                    <div class={s.summaryLine}>
                        {intl.getMessage('encryption_https_summary', { value: httpsPort() })}
                    </div>
                    <div class={s.summaryLine}>
                        {intl.getMessage('encryption_dot_summary', { value: dotPort() })}
                    </div>
                    <div class={s.summaryLine}>
                        {intl.getMessage('encryption_doq_summary', { value: doqPort() })}
                    </div>
                </>
            }
            disabled={!isEnabled()}
            onClick={() => isEnabled() && props.onOpen()}
        />
    );
};

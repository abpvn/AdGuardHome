import { Show, createMemo, createSignal, type JSX } from 'solid-js';
import { useNavigate, useSearchParams } from '@solidjs/router';

import { Banner } from 'panel/common/ui/Banner';
import { Button } from 'panel/common/ui/Button';
import { MANUAL_UPDATE_LINK } from 'panel/helpers/constants';
import { Paths } from 'panel/components/Routes/Paths';
import intl from 'panel/common/intl';
import theme from 'panel/lib/theme';

import { dashboardState, getUpdate } from 'panel/stores/dashboard';
import { encryptionState } from 'panel/stores/encryption';
import {
    type BannerSpec,
    type BannerType,
    bannerSpecsEqual,
    BANNER_TEST_VALUES,
} from 'panel/helpers/banners';

import s from './Banners.module.pcss';

const TLS_EXPIRY_WARNING_MS = 5 * 24 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

type Props = {
    forceBanner?: BannerSpec;
};

export const Banners = (props: Props) => {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams<{ forceBanner?: string }>();
    const [dismissed, setDismissed] = createSignal<BannerSpec | null>(null);

    const forceFromQuery = createMemo(() => {
        const key = searchParams.forceBanner;
        if (key && key in BANNER_TEST_VALUES) {
            return BANNER_TEST_VALUES[key as BannerType];
        }
        return null;
    });

    const getActiveBanners = (): BannerSpec[] => {
        const active: BannerSpec[] = [];

        if (encryptionState.enabled && encryptionState.valid_cert && encryptionState.not_after) {
            const expiry = new Date(encryptionState.not_after).getTime();
            if (!Number.isNaN(expiry)) {
                if (Date.now() > expiry) {
                    active.push({ type: 'tls_expired' });
                } else if (Date.now() > expiry - TLS_EXPIRY_WARNING_MS) {
                    active.push({ type: 'tls_expiring' });
                }
            }
        }

        if (dashboardState.isUpdateAvailable) {
            const spec = {
                version: dashboardState.newVersion,
                announcementUrl: dashboardState.announcementUrl,
            };
            active.push(
                dashboardState.canAutoUpdate
                    ? { type: 'update_auto', ...spec }
                    : { type: 'update_manual', ...spec },
            );
        }

        return active;
    };

    const banner = createMemo<BannerSpec | null>(() => {
        const forced = props.forceBanner ?? forceFromQuery();
        const candidates = forced ? [forced] : getActiveBanners();
        const dismissedValue = dismissed();
        return (
            candidates.find((b) => !(dismissedValue && bannerSpecsEqual(dismissedValue, b))) ??
            null
        );
    });

    const announcementLinkHandler = (announcementUrl: string) => (text: string) => (
        <a href={announcementUrl} class={theme.link.link} target="_blank" rel="noopener noreferrer">
            {text}
        </a>
    );

    return (
        <Show when={banner()} keyed>
            {(current) => {

                const renderBanner = (): JSX.Element => {
                    switch (current.type) {
                        case 'tls_expired':
                            return (
                                <Banner
                                    variant="critical"
                                    message={intl.getMessage('tls_certificate_expired')}
                                    action={
                                        <Button
                                            variant="secondary"
                                            size="very-small"
                                            compact
                                            onClick={() => navigate(Paths.Encryption)}
                                            class={s.actionButton}
                                        >
                                            {intl.getMessage('update_button')}
                                        </Button>
                                    }
                                    onClose={() => setDismissed(current)}
                                    data-testid="banner-tls-expired"
                                />
                            );

                        case 'tls_expiring': {
                            const expiry = new Date(encryptionState.not_after).getTime();
                            const days = Math.ceil((expiry - Date.now()) / DAY_MS);

                            return (
                                <Banner
                                    variant="warning"
                                    message={intl.getPlural('tls_certificate_expiring_days', days)}
                                    action={
                                        <Button
                                            variant="secondary"
                                            size="very-small"
                                            compact
                                            onClick={() => navigate(Paths.Encryption)}
                                            class={s.actionButton}
                                        >
                                            {intl.getMessage('update_button')}
                                        </Button>
                                    }
                                    onClose={() => setDismissed(current)}
                                    data-testid="banner-tls-expiring"
                                />
                            );
                        }

                        case 'update_auto':
                            return (
                                <Banner
                                    variant="info"
                                    message={intl.getMessage('update_available', {
                                        version: current.version,
                                        a: announcementLinkHandler(current.announcementUrl),
                                    })}
                                    action={
                                        <Button
                                            variant="primary"
                                            size="very-small"
                                            compact
                                            disabled={dashboardState.processingUpdate}
                                            onClick={() => getUpdate()}
                                            class={s.actionButton}
                                        >
                                            {intl.getMessage('update_button')}
                                        </Button>
                                    }
                                    onClose={() => setDismissed(current)}
                                    data-testid="banner-update-auto"
                                />
                            );

                        case 'update_manual':
                            return (
                                <Banner
                                    variant="info"
                                    message={intl.getMessage('update_available', {
                                        version: current.version,
                                        a: announcementLinkHandler(current.announcementUrl),
                                    })}
                                    action={
                                        <a
                                            href={MANUAL_UPDATE_LINK}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            class={s.actionLink}
                                        >
                                            <Button
                                                variant="primary"
                                                size="very-small"
                                                compact
                                                class={s.actionButton}
                                            >
                                                {intl.getMessage('update_how_to')}
                                            </Button>
                                        </a>
                                    }
                                    onClose={() => setDismissed(current)}
                                    data-testid="banner-update-manual"
                                />
                            );

                        default:
                            return null;
                    }
                };

                return <div data-testid="banner-root">{renderBanner()}</div>;
            }}
        </Show>
    );
};

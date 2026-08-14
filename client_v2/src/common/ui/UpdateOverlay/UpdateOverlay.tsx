import { Loader } from 'panel/common/ui/Loader';
import intl from 'panel/common/intl';

import s from './UpdateOverlay.module.pcss';

export const UpdateOverlay = () => (
    <div class={s.overlay} role="alert" data-testid="update-overlay">
        <Loader class={s.loader} />
        <p class={s.message}>{intl.getMessage('processing_update')}</p>
    </div>
);

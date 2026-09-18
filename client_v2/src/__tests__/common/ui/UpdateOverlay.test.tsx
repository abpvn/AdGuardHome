import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@solidjs/testing-library';

import { copyInDom } from 'panel/__tests__/helpers/copy';

vi.mock('panel/common/intl', async () =>
    (await import('panel/__tests__/helpers/copy')).createIntlMock(),
);

import { UpdateOverlay } from 'panel/common/ui/UpdateOverlay';

describe('UpdateOverlay', () => {
    it('renders the processing update message', () => {
        render(() => <UpdateOverlay />);

        expect(screen.getByTestId('update-overlay')).toBeInTheDocument();
        expect(screen.getByText(copyInDom('processing_update'))).toBeInTheDocument();
    });
});

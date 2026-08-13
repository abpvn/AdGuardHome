import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@solidjs/testing-library';

vi.mock('panel/common/intl', () => {
    const intl = {
        getMessage: (key: string) => {
            const messages: Record<string, string> = {
                processing_update: 'Please wait, AdGuard Home is being updated',
            };
            return messages[key] || key;
        },
    };
    return { default: intl };
});

import { UpdateOverlay } from 'panel/common/ui/UpdateOverlay';

describe('UpdateOverlay', () => {
    it('renders the processing update message', () => {
        render(() => <UpdateOverlay />);

        expect(screen.getByTestId('update-overlay')).toBeInTheDocument();
        expect(
            screen.getByText('Please wait, AdGuard Home is being updated'),
        ).toBeInTheDocument();
    });
});

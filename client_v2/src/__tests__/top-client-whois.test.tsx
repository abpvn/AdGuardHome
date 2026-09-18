import { describe, it, expect } from 'vitest';
import { render, screen } from '@solidjs/testing-library';

import { Whois } from 'panel/components/Dashboard/blocks/TopClients/Whois';

describe('Dashboard top client Whois', () => {
    it('renders nothing when there is no whois info', () => {
        render(() => <Whois info={{ netname: 'n/a' }} />);
        expect(screen.queryByTestId('top-client-whois')).not.toBeInTheDocument();
    });

    it('renders location and ISP as a single line', () => {
        render(() => <Whois info={{ country: 'US', city: 'Ashburn', orgname: 'Example ISP' }} />);
        expect(screen.getByTestId('top-client-whois')).toHaveTextContent('US,Ashburn | Example ISP');
        expect(screen.getByTestId('top-client-whois').textContent).not.toContain('\n');
    });

    it('renders the country alone when the city is missing', () => {
        render(() => <Whois info={{ country: 'DE', org: 'Another ISP' }} />);
        expect(screen.getByTestId('top-client-whois')).toHaveTextContent('DE | Another ISP');
    });

    it('renders the ISP alone when there is no location', () => {
        render(() => <Whois info={{ orgname: 'Example ISP' }} />);
        expect(screen.getByTestId('top-client-whois')).toHaveTextContent('Example ISP');
    });

    it('renders the location alone when there is no ISP', () => {
        render(() => <Whois info={{ country: 'US', city: 'Ashburn' }} />);
        expect(screen.getByTestId('top-client-whois')).toHaveTextContent('US,Ashburn');
    });
});
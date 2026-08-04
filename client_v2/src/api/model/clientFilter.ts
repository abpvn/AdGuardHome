import type { ClientFilterNames } from './clientFilterNames';

/**
 * Client Filter subscription info
 */
export interface ClientFilter {
    enabled: boolean;
    id: number;
    last_updated?: string;
    name: string;
    names?: ClientFilterNames;
    rules_count: number;
    url: string;
}

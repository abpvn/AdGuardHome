import type { ClientFilter } from './clientFilter';
import type { Filter } from './filter';

/**
 * Filtering settings
 */
export interface FilterStatus {
    enabled?: boolean;
    interval?: number;
    filters?: Filter[];
    whitelist_filters?: Filter[];
    clients_filters?: ClientFilter[];
    user_rules?: string[];
}

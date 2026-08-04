/**
 * Refresh Filters request data
 */
export interface FilterRefreshRequest {
    whitelist?: boolean;
    /** Client name to refresh filter */
    client?: string;
}

/**
 * Client and host access list.  Each of the lists should contain only unique elements.  In addition, allowed and disallowed lists cannot contain the same elements.
 */
export interface AccessList {
    /** The allowlist of clients: IP addresses, CIDRs, or ClientIDs. */
    allowed_clients?: string[];
    /** The blocklist of clients: IP addresses, CIDRs, or ClientIDs. */
    disallowed_clients?: string[];
    /** The blocklist of hosts. */
    blocked_hosts?: string[];
    /** The allowlist of countries: ISO 3166-1 alpha-2 country codes. */
    allowed_countries?: string[];
    /** The blocklist of countries: ISO 3166-1 alpha-2 country codes. */
    blocked_countries?: string[];
}

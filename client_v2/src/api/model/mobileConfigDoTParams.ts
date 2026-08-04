export type MobileConfigDoTParams = {
    /**
     * Host for which the config is generated.  If no host is provided, `tls.server_names` from the configuration file is used.  If `tls.server_names` is not set, the API returns an error with a 500 status.
     */
    host: string;
    /**
     * ClientID.
     */
    client_id?: string;
};

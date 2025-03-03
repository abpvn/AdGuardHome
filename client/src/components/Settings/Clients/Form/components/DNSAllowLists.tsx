import React from "react";
import { useFormContext } from "react-hook-form";
import { Trans, useTranslation } from "react-i18next";
import { ClientForm } from "../types";
import FiltersTable from "../../FiltersTable";

type Props = {
    client: string;
}
export const DNSAllowLists = ({ client }: Props) => {
    const { t } = useTranslation();
    const { watch } = useFormContext<ClientForm>();
    const useGLobalFilters = watch('use_global_filters');
    return (
        <div title={t('dns_allowlists')}>
            {useGLobalFilters ? (
                <Trans>use_global_filters</Trans>
            ) : (
                <FiltersTable client={client} whitelist title={t('dns_allowlists')} />
            )}
        </div>
    );
};

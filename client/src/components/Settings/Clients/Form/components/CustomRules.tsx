import React, { useCallback } from "react";
import { useFormContext } from "react-hook-form";
import { Trans, useTranslation } from "react-i18next";
import { ClientForm } from "../types";
import Examples from "../../../../Filters/Examples";
import { getTextareaCommentsHighlight, syncScroll } from "../../../../../helpers/highlightTextareaComments";
import { COMMENT_LINE_DEFAULT_TOKEN } from "../../../../../helpers/constants";

export const CustomRules = () => {
    const { t } = useTranslation();
    const { watch, setValue } = useFormContext<ClientForm>();
    const useGLobalFilters = watch('use_global_filters');
    const userRules = watch('user_rules');
    
    const ref = React.createRef();

    const onScroll = (e) => syncScroll(e, ref);

    const handleUserRuleChange = useCallback((e) => {
        const { value } = e.currentTarget;
        setValue('user_rules', value || '');
    }, [userRules]);

    return (
        <div title={t('custom_filtering_rules')}>
                {useGLobalFilters ? <Trans>use_global_filters</Trans> : <>
                    <div className="form__desc mb-3">
                        <Trans components={[<a href="#custom_rules" key="0">link</a>]}>
                            custom_rules_client_desc
                        </Trans>
                    </div>
                    <div className='card-subtitle'><Trans>custom_filter_rules_hint</Trans></div>
                    <div className="text-edit-container mt-4 mb-4">
                        <textarea
                            className="form-control font-monospace text-input"
                            value={userRules}
                            onScroll={onScroll}
                            onChange={handleUserRuleChange}
                        />
                        {getTextareaCommentsHighlight(
                            ref,
                            userRules,
                            [COMMENT_LINE_DEFAULT_TOKEN, '!'],
                        )}
                    </div>
                    <hr />
                    <Examples />
                </>}
            </div>
    );
};

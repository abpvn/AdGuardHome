import { createSignal } from 'solid-js';

import { encryptionState, validateTlsConfig } from 'panel/stores/encryption';
import type { ServerSettingsValues } from '../validate';
import { getStepValidationValues, getStoreFormValues } from './helpers';
import { mapStepResult } from './SetupWizard/mapStepResult';

type Options = {
    /** Live form values of the settings dialog; read when a check runs. */
    values: ServerSettingsValues;
};

/** Two name lists describe the same set when their non-empty names match. */
const sameNames = (a: string[], b: string[]) => {
    const left = a.filter((name) => !!name);
    const right = b.filter((name) => !!name);
    return left.length === right.length && left.every((name, i) => name === right[i]);
};

/**
 * Certificate/server-name check behind the "Encrypted DNS server settings"
 * dialog and the TLS setup wizard's config step.
 *
 * Both surfaces edit the names the certificate is checked against, so only the
 * backend can judge them: a check sends the edited draft together with the
 * saved certificate and key and keeps the mismatch warning it reports.  The
 * warning, the live names it belongs to and the check bookkeeping all live
 * here, so the hosts only wire field events to it.
 *
 * The certificate is checked against every name at once, so a warning belongs
 * to the whole list rather than to one row.
 */
export const createServerNameCheck = (opts: Options) => {
    /**
     * Warning plus the names it was reported for.  The live names move on every
     * keystroke while the store only learns them on `change` (blur), so the pair
     * is what keeps the warning from outliving the values it describes.
     */
    const [warning, setWarning] = createSignal<{ names: string[]; text: string }>();
    const [draftNames, setDraftNames] = createSignal<string[]>(['']);

    // Monotonic id used to drop superseded validation responses.
    let checkId = 0;
    // Names of the last completed check, so re-leaving the fields without
    // editing them does not fire another request.
    let lastCheckedNames: string[] | undefined;

    /** The warning to render — only while the fields still hold the checked names. */
    const warningText = () =>
        warning() && sameNames(warning().names, draftNames()) ? warning().text : undefined;

    const hasCert = () =>
        !!(encryptionState.certificate_chain || encryptionState.certificate_path);
    const hasKey = () =>
        !!(
            encryptionState.private_key ||
            encryptionState.private_key_path ||
            encryptionState.private_key_saved
        );

    /**
     * Asks the backend whether the certificate covers the edited server names.
     *
     * `current` is false when a newer check or an edit made the response stale;
     * the caller must then leave the decision to that newer check.  `warning`
     * is the text to show, or undefined when there is nothing to warn about —
     * no certificate to check the names against, names the certificate covers,
     * or a backend verdict other than the server-name mismatch (an unreadable
     * certificate, a busy port) that these surfaces do not render.
     */
    const run = async (): Promise<{ current: boolean; warning?: string }> => {
        const names = [...(opts.values.server_names ?? [])];
        if (!hasCert() || !hasKey()) return { current: true };

        // Validate the edited draft against the saved certificate and key,
        // exactly as the wizard's config step does.
        const formValues = getStoreFormValues({ ...opts.values });
        const payload = getStepValidationValues(3, formValues);

        const id = ++checkId;
        const res = await validateTlsConfig(payload, { persist: false });

        if (id !== checkId || !sameNames(names, draftNames())) {
            return { current: false };
        }

        // The wizard's config step owns this copy, so the same mapping keeps
        // the two surfaces saying the same thing.
        const message = mapStepResult(3, res, formValues);
        const text =
            message?.kind === 'warning' && message.field === 'server_names'
                ? message.message
                : undefined;
        setWarning(text ? { names, text } : undefined);
        lastCheckedNames = names;

        return { current: true, warning: text };
    };

    /** Fills the check with the settings the surface opened with. */
    const reset = (names: string[]) => {
        setWarning(undefined);
        setDraftNames(names);
        lastCheckedNames = undefined;
    };

    /** Keeps the live names in step with the fields, so the warning can be dropped. */
    const onNameInput = (names: string[]) => setDraftNames([...names]);

    /** Checks the names the fields were left with, unless they were already checked. */
    const checkOnBlur = (names: string[]) => {
        if (!lastCheckedNames || !sameNames(names, lastCheckedNames)) void run();
    };

    /**
     * Runs the check for the save and reports whether it may go through.
     *
     * A newly discovered warning has to be seen before it can be saved past: it
     * is put on screen and this attempt is held back, so the next one is
     * visibly a confirmation.  A warning already on screen does not ask again,
     * and a check superseded by a newer one leaves the decision to that check.
     */
    const confirmSave = async (): Promise<boolean> => {
        const shown = warningText();
        const { current, warning: text } = await run();
        if (!current) return false;

        return !text || text === shown;
    };

    return { warningText, reset, onNameInput, checkOnBlur, confirmSave };
};

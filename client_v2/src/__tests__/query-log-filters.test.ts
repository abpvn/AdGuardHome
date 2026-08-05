import { describe, expect, test } from 'vitest';

import {
    DEFAULT_LOGS_FILTER,
    QUERY_LOG_REASON_FILTER,
    QUERY_LOG_STATUS_FILTER,
} from '../helpers/constants';
import { getLogsUrlParams } from '../helpers/helpers';

describe('Query Log filter model', () => {
    test('stores search, status, reason, and client separately', () => {
        expect(DEFAULT_LOGS_FILTER).toEqual({
            search: '',
            status: 'all',
            reason: 'all',
            client: '',
        });
    });

    test('serializes all four filter fields into the URL', () => {
        expect(getLogsUrlParams('example.org', 'blocked', 'FilteredBlockedService')).toBe(
            '?search=example.org&status=blocked&reason=FilteredBlockedService',
        );
        expect(
            getLogsUrlParams('example.org', 'blocked', 'FilteredBlockedService', 'My Phone'),
        ).toBe(
            '?search=example.org&status=blocked&reason=FilteredBlockedService&client=My%20Phone',
        );
    });

    test('drops the client param when empty', () => {
        expect(getLogsUrlParams('', 'all', 'all', '')).not.toContain('client=');
    });

    test('keeps status and reason option sets separate', () => {
        expect(QUERY_LOG_STATUS_FILTER.REWRITTEN.QUERY).toBe('rewritten');
        expect(Object.keys(QUERY_LOG_STATUS_FILTER)).not.toContain('ERROR');
        expect(QUERY_LOG_REASON_FILTER.BLOCKED_BY_FILTER.QUERY).toBe('FilteredBlackList');
        expect(QUERY_LOG_REASON_FILTER.SAFE_SEARCH.QUERY).toBe('FilteredSafeSearch');
    });
});

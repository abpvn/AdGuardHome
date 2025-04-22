import React from 'react';
import { Link } from 'react-router-dom';
import Skeleton, { SkeletonTheme } from 'react-loading-skeleton';
import 'react-loading-skeleton/dist/skeleton.css'

import { useSelector } from 'react-redux';
import { normalizeWhois } from './helpers';
import { THEMES, WHOIS_ICONS } from './constants';
import { RootState } from '../initialState';

const getFormattedWhois = (whois: any) => {
    const whoisInfo = normalizeWhois(whois);
    return Object.keys(whoisInfo).map((key) => {
        const icon = WHOIS_ICONS[key];
        return (
            <span className="logs__whois text-muted" key={key} title={whoisInfo[key]}>
                {icon && (
                    <>
                        <svg className="logs__whois-icon icons icon--18">
                            <use xlinkHref={`#${icon}`} />
                        </svg>
                        &nbsp;
                    </>
                )}
                {whoisInfo[key]}
            </span>
        );
    });
};

// New custom hook for dark mode detection
function useDarkMode(currentTheme: string): boolean {
    const [isDarkModeQuery, setIsDarkModeQuery] = React.useState(
        window.matchMedia('(prefers-color-scheme: dark)').matches,
    );

    React.useEffect(() => {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        const handleModeChange = (event: MediaQueryListEvent) => {
            setIsDarkModeQuery(event.matches);
        };
        mediaQuery.addEventListener('change', handleModeChange);
        return () => mediaQuery.removeEventListener('change', handleModeChange);
    }, []);

    return React.useMemo(() => {
        if (currentTheme === THEMES.auto) {
            return isDarkModeQuery;
        }
        return currentTheme === THEMES.dark;
    }, [currentTheme, isDarkModeQuery]);
}

/**
 * @param {string} value
 * @param {object} info
 * @param {string} info.name
 * @param {object} info.whois_info
 * @param {boolean} [isDetailed]
 * @param {boolean} [isLogs]
 * @param {boolean} [processingClientInfo]
 * @returns {JSXElement}
 */
export const renderFormattedClientCell = (
    value: any,
    info: any,
    isDetailed = false,
    isLogs = false,
    processingClientInfo = false
) => {
    let whoisContainer = null;
    let nameContainer = value;

    const currentTheme = useSelector((state: RootState) => (state.dashboard ? state.dashboard.theme : THEMES.auto));

    // Refactored dark mode logic using the custom hook
    const isDarkMode = useDarkMode(currentTheme);

    if (processingClientInfo) {
        whoisContainer = (
            <div className="logs__text logs__text--wrap logs__text--whois">
                {isDarkMode ? (
                    <SkeletonTheme baseColor="#202020" highlightColor="#444">
                        <Skeleton height={20} />
                    </SkeletonTheme>
                ) : (
                    <Skeleton height={20} />
                )}
            </div>
        );
    } else if (info) {
        const { name, whois_info } = info;
        const whoisAvailable = whois_info && Object.keys(whois_info).length > 0;

        if (name) {
            const nameValue = (
                <div
                    className="logs__text logs__text--link logs__text--nowrap logs__text--client"
                    title={`${name} (${value})`}>
                    {name}&nbsp;<small>{`(${value})`}</small>
                </div>
            );

            if (!isLogs) {
                nameContainer = nameValue;
            } else {
                nameContainer = !whoisAvailable && isDetailed ? <small title={value}>{value}</small> : nameValue;
            }
        }

        if (whoisAvailable && isDetailed) {
            whoisContainer = (
                <div className="logs__text logs__text--wrap logs__text--whois">{getFormattedWhois(whois_info)}</div>
            );
        }
    }

    return (
        <div className="logs__text logs__text--client mw-100" title={value}>
            <Link
                to={`logs?${info?.name === value ? `client=${encodeURIComponent(value)}` : `search="${encodeURIComponent(value)}"`}`}>
                {nameContainer}
            </Link>
            {whoisContainer}
        </div>
    );
};

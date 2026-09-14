import { createMemo } from 'solid-js';
import { TOP_CLIENTS_VISIBLE_ITEMS } from 'panel/helpers/constants';

export { TOP_CLIENTS_VISIBLE_ITEMS };

type SortableItem = {
    count: number;
};

export const DEFAULT_VISIBLE_ITEMS = 5;

export const useSortedData = <T extends SortableItem>(
    data: () => T[],
    limit: number = DEFAULT_VISIBLE_ITEMS,
): { sortedData: () => T[] } => {
    const sortedData = createMemo(() =>
        data()
            .toSorted((a, b) => b.count - a.count)
            .slice(0, limit),
    );

    return { sortedData };
};

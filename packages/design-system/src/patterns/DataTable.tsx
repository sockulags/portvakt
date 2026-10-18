import type { ReactNode } from "react";
import { Button, Checkbox, Skeleton } from "../components/index";
import { Icon } from "./icons";
import styles from "./DataTable.module.css";

export type SortDirection = "asc" | "desc";

export interface DataTableColumn<T> {
  key: string;
  header: string;
  cell: (row: T) => ReactNode;
  sortable?: boolean;
  /** Numbers and amounts read best aligned to the end. */
  align?: "start" | "end";
  width?: string;
}

export interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  /** Describes the table for screen readers. */
  caption: string;
  sort?: { key: string; direction: SortDirection };
  onSortChange?: (sort: { key: string; direction: SortDirection }) => void;
  selectable?: boolean;
  selected?: string[];
  onSelectedChange?: (keys: string[]) => void;
  loading?: boolean;
  /** Shown instead of rows when there are none. */
  empty?: ReactNode;
  density?: "comfortable" | "compact";
  /** Pins the hover state on the row with this key, for the gallery. */
  forceHover?: string;
  /** Under the table, typically pagination. */
  footer?: ReactNode;
}

const LOADING_ROWS = 5;

/** A sortable, selectable table with loading and empty states. */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  caption,
  sort,
  onSortChange,
  selectable = false,
  selected = [],
  onSelectedChange,
  loading = false,
  empty,
  density = "comfortable",
  forceHover,
  footer,
}: DataTableProps<T>) {
  const keys = rows.map(rowKey);
  const allSelected = keys.length > 0 && keys.every((key) => selected.includes(key));
  const someSelected = !allSelected && keys.some((key) => selected.includes(key));
  const span = columns.length + (selectable ? 1 : 0);

  const toggleAll = () => onSelectedChange?.(allSelected ? [] : keys);
  const toggle = (key: string) =>
    onSelectedChange?.(selected.includes(key) ? selected.filter((item) => item !== key) : [...selected, key]);

  const sortBy = (key: string) => {
    const direction: SortDirection = sort?.key === key && sort.direction === "asc" ? "desc" : "asc";
    onSortChange?.({ key, direction });
  };

  return (
    <div className={styles.frame} data-ds="data-table" data-density={density}>
      <div className={styles.scroll}>
        <table className={styles.table} aria-busy={loading || undefined}>
          <caption className={styles.caption}>{caption}</caption>
          <thead>
            <tr>
              {selectable && (
                <th scope="col" className={styles.check}>
                  <Checkbox
                    aria-label="Select all rows"
                    checked={allSelected}
                    indeterminate={someSelected}
                    disabled={loading || rows.length === 0}
                    onChange={toggleAll}
                  />
                </th>
              )}
              {columns.map((column) => {
                const sorted = sort?.key === column.key ? sort.direction : undefined;
                return (
                  <th
                    key={column.key}
                    scope="col"
                    style={{ width: column.width }}
                    data-align={column.align}
                    aria-sort={sorted ? (sorted === "asc" ? "ascending" : "descending") : undefined}
                  >
                    {column.sortable ? (
                      <button type="button" className={styles.sort} data-active={sorted ? true : undefined} onClick={() => sortBy(column.key)}>
                        {column.header}
                        <Icon name={sorted === "asc" ? "sort-up" : sorted === "desc" ? "sort-down" : "sort"} size={14} />
                      </button>
                    ) : (
                      column.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {loading &&
              Array.from({ length: LOADING_ROWS }, (_, index) => (
                <tr key={`loading-${index}`}>
                  {selectable && (
                    <td className={styles.check}>
                      <Skeleton width={16} height={16} />
                    </td>
                  )}
                  {columns.map((column, columnIndex) => (
                    <td key={column.key} data-align={column.align}>
                      <Skeleton width={`${55 + ((index * 17 + columnIndex * 23) % 40)}%`} />
                    </td>
                  ))}
                </tr>
              ))}
            {!loading && rows.length === 0 && (
              <tr>
                <td colSpan={span} className={styles.empty}>
                  {empty ?? "Nothing here yet."}
                </td>
              </tr>
            )}
            {!loading &&
              rows.map((row) => {
                const key = rowKey(row);
                const isSelected = selected.includes(key);
                return (
                  <tr key={key} data-selected={isSelected || undefined} data-force={forceHover === key ? "hover" : undefined}>
                    {selectable && (
                      <td className={styles.check}>
                        <Checkbox aria-label={`Select row ${key}`} checked={isSelected} onChange={() => toggle(key)} />
                      </td>
                    )}
                    {columns.map((column) => (
                      <td key={column.key} data-align={column.align}>
                        {column.cell(row)}
                      </td>
                    ))}
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>
      {footer && <div className={styles.footer}>{footer}</div>}
    </div>
  );
}

export interface PaginationProps {
  page: number;
  pageCount: number;
  onPageChange?: (page: number) => void;
  /** Text on the left, such as "Showing 11–20 of 48". */
  summary?: ReactNode;
}

/** Page numbers with gaps: 1 … 4 5 6 … 12. */
function pageList(page: number, count: number): (number | "gap")[] {
  const wanted = new Set([1, count, page - 1, page, page + 1].filter((value) => value >= 1 && value <= count));
  const sorted = [...wanted].sort((a, b) => a - b);
  const list: (number | "gap")[] = [];
  sorted.forEach((value, index) => {
    const previous = sorted[index - 1];
    if (previous !== undefined && value - previous > 1) list.push(value - previous === 2 ? value - 1 : "gap");
    list.push(value);
  });
  return list;
}

/** Moves through pages of a long list. */
export function Pagination({ page, pageCount, onPageChange, summary }: PaginationProps) {
  return (
    <nav className={styles.pagination} aria-label="Pagination" data-ds="pagination">
      {summary && <span className={styles.summary}>{summary}</span>}
      <div className={styles.pages}>
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onPageChange?.(page - 1)} aria-label="Previous page">
          <Icon name="chevron-left" size={14} />
        </Button>
        {pageList(page, pageCount).map((item, index) =>
          item === "gap" ? (
            <span key={`gap-${index}`} className={styles.gap} aria-hidden>
              …
            </span>
          ) : (
            <button
              key={item}
              type="button"
              className={styles.page}
              aria-current={item === page ? "page" : undefined}
              aria-label={`Page ${item}`}
              onClick={() => onPageChange?.(item)}
            >
              {item}
            </button>
          ),
        )}
        <Button size="sm" variant="ghost" disabled={page >= pageCount} onClick={() => onPageChange?.(page + 1)} aria-label="Next page">
          <Icon name="chevron-right" size={14} />
        </Button>
      </div>
    </nav>
  );
}

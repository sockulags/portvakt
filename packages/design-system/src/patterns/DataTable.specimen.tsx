import { useMemo, useState } from "react";
import { Avatar, Badge, Button } from "../components/index";
import { defineSpecimen } from "../components/specimen";
import { DataTable, Pagination, type DataTableColumn, type SortDirection } from "./DataTable";
import { EmptyState } from "./EmptyState";
import { initials, MEMBERS, type Member } from "./specimen-data";

const STATUS_COLOR = { Active: "success", Invited: "info", Suspended: "danger" } as const;

const COLUMNS: DataTableColumn<Member>[] = [
  {
    key: "name",
    header: "Name",
    sortable: true,
    cell: (member) => (
      <span style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
        <Avatar initials={initials(member.name)} />
        <span>
          <span style={{ display: "block", fontWeight: "var(--weight-medium)" }}>{member.name}</span>
          <span style={{ color: "var(--color-text-muted)", fontSize: "var(--text-xs)" }}>{member.email}</span>
        </span>
      </span>
    ),
  },
  { key: "role", header: "Role", sortable: true, cell: (member) => member.role },
  { key: "status", header: "Status", cell: (member) => <Badge color={STATUS_COLOR[member.status]}>{member.status}</Badge> },
  { key: "projects", header: "Projects", sortable: true, align: "end", cell: (member) => member.projects },
  { key: "lastActive", header: "Last active", cell: (member) => <span style={{ color: "var(--color-text-muted)" }}>{member.lastActive}</span> },
];

function sorted(rows: Member[], sort: { key: string; direction: SortDirection }) {
  const factor = sort.direction === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => {
    const left = a[sort.key as keyof Member];
    const right = b[sort.key as keyof Member];
    return (typeof left === "number" && typeof right === "number" ? left - right : String(left).localeCompare(String(right))) * factor;
  });
}

export default defineSpecimen([
  {
    id: "data-table",
    title: "Data table",
    group: "Data",
    description: "Sortable, selectable rows with loading, empty and compact variants, plus pagination.",
    order: 40,
    blocks: [
      {
        kind: "block",
        title: "Live · sort by a column, select rows",
        render: function LiveTable() {
          const [sort, setSort] = useState<{ key: string; direction: SortDirection }>({ key: "name", direction: "asc" });
          const [selected, setSelected] = useState<string[]>(["m2"]);
          const [page, setPage] = useState(1);
          const rows = useMemo(() => sorted(MEMBERS, sort), [sort]);
          return (
            <DataTable
              caption="Workspace members"
              columns={COLUMNS}
              rows={rows}
              rowKey={(member) => member.id}
              sort={sort}
              onSortChange={setSort}
              selectable
              selected={selected}
              onSelectedChange={setSelected}
              footer={
                <Pagination
                  page={page}
                  pageCount={6}
                  onPageChange={setPage}
                  summary={selected.length ? `${selected.length} selected` : `Showing ${(page - 1) * 7 + 1}–${page * 7} of 42`}
                />
              }
            />
          );
        },
      },
      {
        kind: "block",
        title: "Row states · selected and hover pinned, compact density",
        render: () => (
          <DataTable
            caption="Row states"
            columns={COLUMNS.filter((column) => column.key !== "lastActive")}
            rows={MEMBERS.slice(0, 4)}
            rowKey={(member) => member.id}
            selectable
            selected={["m1", "m3"]}
            forceHover="m2"
            density="compact"
          />
        ),
      },
      {
        kind: "grid",
        title: "Loading and empty",
        min: 360,
        items: [
          {
            label: "loading",
            render: () => (
              <div style={{ width: "100%" }}>
                <DataTable caption="Loading" columns={COLUMNS.slice(0, 3)} rows={[]} rowKey={(member: Member) => member.id} loading selectable />
              </div>
            ),
          },
          {
            label: "empty",
            render: () => (
              <div style={{ width: "100%" }}>
                <DataTable
                  caption="No results"
                  columns={COLUMNS.slice(0, 3)}
                  rows={[]}
                  rowKey={(member: Member) => member.id}
                  empty={
                    <EmptyState
                      compact
                      icon="search"
                      title="No members match “sales”"
                      description="Check the spelling or clear the filter."
                      actions={<Button size="sm" variant="secondary">Clear filter</Button>}
                    />
                  }
                />
              </div>
            ),
          },
        ],
      },
      {
        kind: "block",
        title: "Pagination · first, middle and last page",
        render: function Pages() {
          const [page, setPage] = useState(5);
          return (
            <div style={{ display: "grid", gap: "var(--space-4)" }}>
              <Pagination page={1} pageCount={12} summary="Page 1 of 12" />
              <Pagination page={page} pageCount={12} onPageChange={setPage} summary={`Page ${page} of 12 · live`} />
              <Pagination page={12} pageCount={12} summary="Page 12 of 12" />
            </div>
          );
        },
      },
    ],
  },
]);

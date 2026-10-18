import { useState } from "react";
import { Avatar, Badge, Button } from "../components/index";
import { defineSpecimen } from "../components/specimen";
import { AppShell } from "./AppShell";
import { DataTable, Pagination, type DataTableColumn } from "./DataTable";
import { Icon } from "./icons";
import { Navbar } from "./Navbar";
import { PageHeader } from "./PageHeader";
import { SidebarNav } from "./SidebarNav";
import { initials, MEMBERS, NAV_LINKS, SIDEBAR_SECTIONS, type Member } from "./specimen-data";
import { StatCard } from "./StatCard";

const COLUMNS: DataTableColumn<Member>[] = [
  {
    key: "name",
    header: "Name",
    cell: (member) => (
      <span style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
        <Avatar initials={initials(member.name)} />
        {member.name}
      </span>
    ),
  },
  { key: "role", header: "Role", cell: (member) => member.role },
  {
    key: "status",
    header: "Status",
    cell: (member) => (
      <Badge color={member.status === "Active" ? "success" : member.status === "Invited" ? "info" : "danger"}>{member.status}</Badge>
    ),
  },
  { key: "projects", header: "Projects", align: "end", cell: (member) => member.projects },
];

export default defineSpecimen({
  id: "app-shell",
  title: "Application shell",
  group: "Examples",
  description: "The patterns together: navbar, sidebar, page header, stats and a table in one working screen.",
  order: 80,
  blocks: [
    {
      kind: "block",
      render: function Dashboard() {
        const [section, setSection] = useState("team");
        const [link, setLink] = useState("team");
        const [selected, setSelected] = useState<string[]>([]);
        return (
          <div
            style={{
              height: 720,
              overflow: "hidden",
              border: "var(--border-thin) solid var(--color-border)",
              borderRadius: "var(--radius-xl)",
              boxShadow: "var(--shadow-lg)",
            }}
          >
            <AppShell
              contained
              navbar={
                <Navbar
                  brand="Northwind"
                  links={NAV_LINKS}
                  active={link}
                  onNavigate={setLink}
                  searchPlaceholder="Search…"
                  user={{ initials: "AL", name: "Ada Lovelace" }}
                />
              }
              sidebar={<SidebarNav sections={SIDEBAR_SECTIONS} active={section} onNavigate={setSection} />}
            >
              <div style={{ display: "grid", gap: "var(--space-6)", padding: "var(--space-6) var(--space-8)" }}>
                <PageHeader
                  breadcrumbs={[{ label: "Workspace" }, { label: "Team" }]}
                  title="Team"
                  description="Seven people have access to Northwind."
                  actions={
                    <Button>
                      <Icon name="plus" size={14} />
                      Invite people
                    </Button>
                  }
                />
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "var(--space-4)" }}>
                  <StatCard label="Members" value="7" delta={{ value: "2", direction: "up" }} hint="this month" />
                  <StatCard label="Pending invites" value="1" delta={{ value: "0", direction: "flat" }} />
                  <StatCard label="Active today" value="5" trend={[2, 3, 3, 4, 3, 5, 5]} />
                </div>
                <DataTable
                  caption="Members"
                  columns={COLUMNS}
                  rows={MEMBERS}
                  rowKey={(member) => member.id}
                  selectable
                  selected={selected}
                  onSelectedChange={setSelected}
                  footer={<Pagination page={1} pageCount={1} summary={`${MEMBERS.length} members`} />}
                />
              </div>
            </AppShell>
          </div>
        );
      },
    },
  ],
});

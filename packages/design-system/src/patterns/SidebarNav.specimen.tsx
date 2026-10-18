import { useState } from "react";
import { Avatar } from "../components/index";
import { defineSpecimen } from "../components/specimen";
import { SidebarNav } from "./SidebarNav";
import { SIDEBAR_SECTIONS } from "./specimen-data";

const frame = {
  height: 500,
  overflow: "hidden",
  border: "var(--border-thin) solid var(--color-border)",
  borderRadius: "var(--radius-lg)",
} as const;

const workspace = (
  <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", fontWeight: "var(--weight-semibold)", fontSize: "var(--text-sm)" }}>
    <span aria-hidden style={{ width: 24, height: 24, borderRadius: "var(--radius-sm)", background: "var(--color-primary)", flex: "none" }} />
    Northwind
  </div>
);

const user = (
  <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", fontSize: "var(--text-sm)" }}>
    <Avatar initials="AL" />
    <span>
      Ada Lovelace
      <br />
      <span style={{ color: "var(--color-text-muted)", fontSize: "var(--text-xs)" }}>Owner</span>
    </span>
  </div>
);

export default defineSpecimen({
  id: "sidebar-nav",
  title: "Sidebar",
  group: "Navigation",
  description: "Side navigation with grouped links, icons and counts, and a collapsed rail for more room.",
  order: 20,
  blocks: [
    {
      kind: "row",
      title: "Expanded, collapsed, and with hover and focus-visible pinned",
      render: function Sidebars() {
        const [active, setActive] = useState("inbox");
        return (
          <>
            <div style={frame}>
              <SidebarNav sections={SIDEBAR_SECTIONS} active={active} onNavigate={setActive} header={workspace} footer={user} />
            </div>
            <div style={frame}>
              <SidebarNav sections={SIDEBAR_SECTIONS} active={active} onNavigate={setActive} collapsed />
            </div>
            <div style={frame}>
              <SidebarNav
                sections={SIDEBAR_SECTIONS.map((section, sectionIndex) => ({
                  ...section,
                  items: section.items.map((item, index) => ({
                    ...item,
                    force: sectionIndex === 0 && index === 2 ? "hover" : sectionIndex === 0 && index === 3 ? "focus" : undefined,
                    disabled: sectionIndex === 1 && index === 1,
                  })),
                }))}
                active="home"
              />
            </div>
          </>
        );
      },
    },
  ],
});

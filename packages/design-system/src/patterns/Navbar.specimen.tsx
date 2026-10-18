import { useState } from "react";
import { Button } from "../components/index";
import { defineSpecimen } from "../components/specimen";
import { Icon } from "./icons";
import { Navbar } from "./Navbar";
import { NAV_LINKS } from "./specimen-data";

const frame = {
  overflow: "hidden",
  border: "var(--border-thin) solid var(--color-border)",
  borderRadius: "var(--radius-lg)",
  background: "var(--color-bg)",
} as const;

const brand = (
  <>
    <span
      aria-hidden
      style={{ width: 22, height: 22, borderRadius: "var(--radius-sm)", background: "var(--color-primary)", display: "inline-block" }}
    />
    Northwind
  </>
);

const actions = (
  <>
    <Button size="sm" variant="ghost" aria-label="Notifications">
      <Icon name="bell" />
    </Button>
    <Button size="sm">
      <Icon name="plus" size={14} />
      New project
    </Button>
  </>
);

export default defineSpecimen({
  id: "navbar",
  title: "Navbar",
  group: "Navigation",
  description: "The top bar of an application: brand, primary links, search, actions and the signed-in user.",
  order: 10,
  blocks: [
    {
      kind: "block",
      title: "Default · click the links",
      render: function LiveNavbar() {
        const [active, setActive] = useState("projects");
        return (
          <div style={frame}>
            <Navbar
              brand={brand}
              links={NAV_LINKS}
              active={active}
              onNavigate={setActive}
              searchPlaceholder="Search projects…"
              actions={actions}
              user={{ initials: "AL", name: "Ada Lovelace" }}
            />
          </div>
        );
      },
    },
    {
      kind: "block",
      title: "Link states · hover and focus-visible pinned",
      render: () => (
        <div style={frame}>
          <Navbar
            brand={brand}
            links={NAV_LINKS.map((link, index) => ({ ...link, force: index === 1 ? "hover" : index === 2 ? "focus" : undefined }))}
            active="overview"
            user={{ initials: "AL", name: "Ada Lovelace" }}
          />
        </div>
      ),
    },
    {
      kind: "block",
      title: "Elevated · after the page scrolls under it",
      render: () => (
        <div style={{ ...frame, paddingBottom: "var(--space-6)" }}>
          <Navbar brand={brand} links={NAV_LINKS} active="team" elevated user={{ initials: "AL", name: "Ada Lovelace" }} />
        </div>
      ),
    },
    {
      kind: "block",
      title: "Compact · narrow screens, open the menu",
      render: function CompactNavbar() {
        const [open, setOpen] = useState(false);
        return (
          <div style={{ ...frame, maxWidth: 380 }}>
            <Navbar
              brand={brand}
              links={NAV_LINKS}
              active="overview"
              compact
              menuOpen={open}
              onMenuToggle={() => setOpen((value) => !value)}
              user={{ initials: "AL", name: "Ada Lovelace" }}
            />
          </div>
        );
      },
    },
  ],
});

import { useState } from "react";
import { Badge, Button, Tabs } from "../components/index";
import { defineSpecimen, type RenderProps } from "../components/specimen";
import { Icon } from "./icons";
import { Breadcrumbs, PageHeader } from "./PageHeader";

export default defineSpecimen({
  id: "page-header",
  title: "Page header",
  group: "Navigation",
  description: "The top of a page: where you are, what this is, and the actions that belong to it.",
  order: 30,
  blocks: [
    {
      kind: "block",
      title: "Full · breadcrumbs, status, actions and tabs",
      render: function FullHeader({ design }: RenderProps) {
        const [tab, setTab] = useState("overview");
        return (
          <PageHeader
            breadcrumbs={[{ label: "Projects" }, { label: "Northwind" }, { label: "Website relaunch" }]}
            title="Website relaunch"
            meta={
              <>
                <Badge color="success">On track</Badge>
                <Badge>Due 14 Nov</Badge>
              </>
            }
            description="Rebuild the marketing site on the new design system and move the blog off the old CMS."
            actions={
              <>
                <Button variant="secondary">Share</Button>
                <Button>
                  <Icon name="plus" size={14} />
                  New task
                </Button>
              </>
            }
          >
            <Tabs
              label="Project sections"
              variant={design.components.tabs?.variant ?? "underline"}
              value={tab}
              onChange={setTab}
              items={[
                { id: "overview", label: "Overview" },
                { id: "tasks", label: "Tasks" },
                { id: "files", label: "Files" },
                { id: "settings", label: "Settings" },
              ]}
            />
          </PageHeader>
        );
      },
    },
    {
      kind: "block",
      title: "Minimal · title and one action",
      render: () => <PageHeader title="Team" description="People with access to this workspace." actions={<Button>Invite people</Button>} />,
    },
    {
      kind: "row",
      title: "Breadcrumbs",
      render: () => <Breadcrumbs items={[{ label: "Home" }, { label: "Settings" }, { label: "Billing" }, { label: "Invoices" }]} />,
    },
  ],
});

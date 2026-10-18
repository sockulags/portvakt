import { useState } from "react";
import { defineSpecimen } from "./specimen";
import { Tabs } from "./Tabs";

export default defineSpecimen({
  id: "navigation",
  title: "Tabs",
  description: "The look comes from components.tabs.variant in the tokens. Use the arrow keys in the live tabs to move focus.",
  order: 50,
  blocks: [
    {
      kind: "block",
      title: "States · selected, hover, focus-visible, disabled",
      render: ({ design }) => (
        <Tabs
          label="Tab states"
          variant={design.components.tabs?.variant ?? "underline"}
          value="overview"
          items={[
            { id: "overview", label: "Overview" },
            { id: "activity", label: "Activity", force: "hover" },
            { id: "members", label: "Members", force: "focus" },
            { id: "billing", label: "Billing", disabled: true },
          ]}
        />
      ),
    },
    {
      kind: "block",
      title: "Live",
      render: function LiveTabs({ design }) {
        const [tab, setTab] = useState("overview");
        return (
          <Tabs
            label="Project sections"
            variant={design.components.tabs?.variant ?? "underline"}
            value={tab}
            onChange={setTab}
            items={[
              { id: "overview", label: "Overview" },
              { id: "activity", label: "Activity" },
              { id: "members", label: "Members" },
              { id: "settings", label: "Settings" },
            ]}
          />
        );
      },
    },
  ],
});

import { useState } from "react";
import { Button } from "./Button";
import { DialogStage, Tooltip } from "./Overlay";
import { defineSpecimen } from "./specimen";

export default defineSpecimen({
  id: "overlays",
  title: "Tooltips & dialogs",
  description: "Floating layers. Hover the live tooltip; replay the dialog to judge its enter motion.",
  order: 70,
  blocks: [
    {
      kind: "row",
      title: "Tooltip · static and live",
      render: () => (
        <>
          <div style={{ paddingTop: 44, marginRight: "var(--space-6)" }}>
            <Tooltip text="Copied to clipboard" open>
              <Button variant="secondary">Static</Button>
            </Tooltip>
          </div>
          <div style={{ paddingTop: 44 }}>
            <Tooltip text="Opens in a new tab">
              <Button variant="outline">Hover me</Button>
            </Tooltip>
          </div>
        </>
      ),
    },
    {
      kind: "block",
      title: "Dialog",
      render: function DialogDemo() {
        const [replay, setReplay] = useState(0);
        return (
          <div style={{ display: "grid", justifyItems: "start", gap: "var(--space-3)" }}>
            <Button size="sm" variant="secondary" onClick={() => setReplay((value) => value + 1)}>
              Replay enter
            </Button>
            <div style={{ width: "100%" }}>
              <DialogStage
                key={replay}
                animate={replay > 0}
                title="Archive this project?"
                footer={
                  <>
                    <Button variant="ghost">Cancel</Button>
                    <Button variant="danger">Archive</Button>
                  </>
                }
              >
                Archived projects stay readable for 30 days. After that, their history is removed for good.
              </DialogStage>
            </div>
          </div>
        );
      },
    },
  ],
});

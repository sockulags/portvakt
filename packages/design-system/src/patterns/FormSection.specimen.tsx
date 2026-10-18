import { useState } from "react";
import { Button, Field, Radio, Select, Switch, Textarea, TextInput } from "../components/index";
import { defineSpecimen } from "../components/specimen";
import { FormActions, FormLayout, FormSection } from "./FormSection";

export default defineSpecimen({
  id: "forms",
  title: "Form sections",
  group: "Forms",
  description: "Long forms as titled sections: the explanation beside the fields on wide screens, above them on narrow ones.",
  order: 60,
  blocks: [
    {
      kind: "block",
      title: "Settings form · try saving with an empty name",
      render: function SettingsForm() {
        const [name, setName] = useState("Northwind");
        const [submitted, setSubmitted] = useState(false);
        const [visibility, setVisibility] = useState("team");
        const invalid = submitted && !name.trim();
        return (
          <FormLayout
            onSubmit={(event) => {
              event.preventDefault();
              setSubmitted(true);
            }}
          >
            <FormSection title="Workspace" description="How the workspace appears to members and in emails.">
              <Field label="Name" error={invalid ? "Give the workspace a name" : undefined}>
                <TextInput value={name} onChange={(event) => setName(event.target.value)} invalid={invalid} />
              </Field>
              <Field label="Description" hint="Shown on the members' home page.">
                <Textarea defaultValue="Product and design team for the Northwind relaunch." />
              </Field>
            </FormSection>
            <FormSection title="Access" description="Who can find and join this workspace.">
              <Field label="Default role">
                <Select defaultValue="editor">
                  <option value="viewer">Viewer</option>
                  <option value="editor">Editor</option>
                  <option value="admin">Admin</option>
                </Select>
              </Field>
              <div role="radiogroup" aria-label="Visibility" style={{ display: "grid", gap: "var(--space-2)" }}>
                <Radio label="Only invited people" name="visibility" checked={visibility === "invite"} onChange={() => setVisibility("invite")} />
                <Radio label="Anyone in the team" name="visibility" checked={visibility === "team"} onChange={() => setVisibility("team")} />
              </div>
            </FormSection>
            <FormSection title="Notifications" description="Email summaries for workspace activity.">
              <Switch label="Weekly digest" defaultChecked />
              <Switch label="Mentions and replies" defaultChecked />
            </FormSection>
            <FormActions note={submitted && !invalid ? "Saved just now." : "Changes apply to every member."}>
              <Button variant="ghost" onClick={() => setSubmitted(false)}>
                Cancel
              </Button>
              <Button type="submit">Save changes</Button>
            </FormActions>
          </FormLayout>
        );
      },
    },
  ],
});

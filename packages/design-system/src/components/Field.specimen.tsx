import { Field, Select, Textarea, TextInput } from "./Field";
import { defineSpecimen } from "./specimen";

export default defineSpecimen({
  id: "inputs",
  title: "Inputs",
  description:
    "Text fields, select and textarea through every state they can be in: resting, hovered, focused, filled, invalid, disabled and read-only.",
  order: 20,
  blocks: [
    {
      kind: "grid",
      title: "Text input states",
      min: 200,
      items: [
        {
          label: "default",
          render: () => (
            <Field label="Default" hint="Helper text sits here">
              <TextInput placeholder="name@company.com" />
            </Field>
          ),
        },
        {
          label: "hover",
          render: () => (
            <Field label="Hover">
              <TextInput placeholder="name@company.com" force="hover" />
            </Field>
          ),
        },
        {
          label: "focus",
          render: () => (
            <Field label="Focus">
              <TextInput placeholder="name@company.com" force="focus" />
            </Field>
          ),
        },
        {
          label: "filled",
          render: () => (
            <Field label="Filled">
              <TextInput defaultValue="ada@lovelace.dev" />
            </Field>
          ),
        },
        {
          label: "invalid",
          render: () => (
            <Field label="Invalid" error="Enter a valid email address">
              <TextInput defaultValue="ada@" invalid />
            </Field>
          ),
        },
        {
          label: "invalid + focus",
          render: () => (
            <Field label="Invalid + focus" error="Enter a valid email address">
              <TextInput defaultValue="ada@" invalid force="focus" />
            </Field>
          ),
        },
        {
          label: "disabled",
          render: () => (
            <Field label="Disabled">
              <TextInput placeholder="Not editable" disabled />
            </Field>
          ),
        },
        {
          label: "read-only",
          render: () => (
            <Field label="Read-only">
              <TextInput defaultValue="ws_4f9a21" readOnly />
            </Field>
          ),
        },
      ],
    },
    {
      kind: "grid",
      title: "Select & textarea",
      min: 240,
      items: [
        {
          label: "select",
          render: () => (
            <Field label="Select">
              <Select defaultValue="team">
                <option value="solo">Solo</option>
                <option value="team">Team</option>
                <option value="org">Organisation</option>
              </Select>
            </Field>
          ),
        },
        {
          label: "select · focus",
          render: () => (
            <Field label="Select · focus">
              <Select defaultValue="team" force="focus">
                <option value="team">Team</option>
              </Select>
            </Field>
          ),
        },
        {
          label: "select · disabled",
          render: () => (
            <Field label="Select · disabled">
              <Select defaultValue="team" disabled>
                <option value="team">Team</option>
              </Select>
            </Field>
          ),
        },
        {
          label: "textarea",
          render: () => (
            <Field label="Textarea" hint="Markdown is supported">
              <Textarea placeholder="Tell us about your project…" />
            </Field>
          ),
        },
        {
          label: "textarea · invalid",
          render: () => (
            <Field label="Textarea · invalid" error="Please write at least 20 characters">
              <Textarea defaultValue="Too short" invalid />
            </Field>
          ),
        },
      ],
    },
  ],
});

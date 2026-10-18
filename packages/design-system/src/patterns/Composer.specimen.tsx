import { useState } from "react";
import { Button } from "../components/index";
import { defineSpecimen } from "../components/specimen";
import { Composer, type ComposerAttachment, type ComposerProps } from "./Composer";
import { Icon } from "./icons";

const FILES: ComposerAttachment[] = [
  { id: "a1", name: "churn-report-q3.pdf", meta: "PDF · 2.4 MB" },
  { id: "a2", name: "survey-responses.csv", meta: "CSV · 380 KB" },
];

const LONG =
  "Here is what I need for the board update on Thursday.\n\n" +
  "1. A one-paragraph summary of why churn rose in September, using the attached report.\n" +
  "2. The three customer quotes from the survey that explain it best.\n" +
  "3. What we already changed in onboarding, and what we plan next quarter.\n" +
  "4. One chart: monthly churn for the last twelve months, with the pricing change marked.\n\n" +
  "Keep it under a page, plain language, no internal team names. If something in the data looks off, " +
  "point it out instead of smoothing it over.";

const mode = (
  <Button variant="ghost" size="sm">
    Balanced
    <Icon name="chevron-down" size={12} />
  </Button>
);

/** A composer that keeps its own text and attachments, so every state can be typed in and sent. */
function Live({
  text = "",
  files = [],
  ...rest
}: Omit<ComposerProps, "value" | "attachments"> & { text?: string; files?: ComposerAttachment[] }) {
  const [value, setValue] = useState(text);
  const [attachments, setAttachments] = useState(files);
  return (
    <Composer
      value={value}
      onValueChange={setValue}
      onSubmit={() => {
        setValue("");
        setAttachments([]);
      }}
      attachments={attachments}
      onAttach={() =>
        setAttachments((current) => [
          ...current,
          { id: `f${current.length + 1}`, name: `notes-${current.length + 1}.md`, meta: "Markdown · 4 KB" },
        ])
      }
      onRemoveAttachment={(id) => setAttachments((current) => current.filter((file) => file.id !== id))}
      tools={mode}
      {...rest}
    />
  );
}

/** Stop ends the reply, after which the composer can send again. */
function Replying() {
  const [busy, setBusy] = useState(true);
  return <Live busy={busy} onStop={() => setBusy(false)} placeholder="Reply…" />;
}

export default defineSpecimen({
  id: "composer",
  title: "Composer",
  group: "Chat",
  description:
    "Where a message is written. The field grows with its content, Enter sends and Shift+Enter starts a new line. " +
    "While a reply is on its way, Send becomes Stop.",
  order: 74,
  blocks: [
    {
      kind: "states",
      states: [
        { label: "empty", render: () => <Live placeholder="Ask anything about your workspace…" /> },
        {
          label: "written",
          render: () => <Live text="Summarise the open support tickets from this week, grouped by product area." />,
        },
        {
          label: "attachments",
          render: () => (
            <Live
              text="What explains the rise in churn?"
              files={[...FILES, { id: "a3", name: "interviews.docx", meta: "Uploading…", uploading: true }]}
            />
          ),
        },
        {
          label: "replying",
          render: Replying,
        },
        {
          label: "focus",
          render: () => <Live force="focus" footer="Answers can be wrong. Check anything important." />,
        },
        {
          label: "disabled",
          render: () => <Live disabled placeholder="You have used this month's messages. They renew on the 1st." />,
        },
        { label: "long content", render: () => <Live text={LONG} files={FILES} maxRows={6} /> },
      ],
    },
  ],
});

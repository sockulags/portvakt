import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button } from "../components/index";
import { defineSpecimen } from "../components/specimen";
import { ChatMessage, ChatThread, ChatWelcome, type ChatSuggestion } from "./Chat";
import { Composer } from "./Composer";

const frame = {
  height: 520,
  border: "var(--border-thin) solid var(--color-border)",
  borderRadius: "var(--radius-lg)",
  overflow: "hidden",
} as const;

const SUGGESTIONS: ChatSuggestion[] = [
  { id: "summary", icon: "inbox", label: "Summarise this week's tickets", description: "Grouped by product area" },
  { id: "churn", icon: "chart", label: "Explain the churn trend", description: "Using the September report" },
  { id: "team", icon: "users", label: "Draft a team update", description: "Short, for Friday's email" },
  { id: "search", icon: "search", label: "Find a past decision", description: "Across notes and documents" },
];

const PROMPTS: Record<string, string> = {
  summary: "Summarise this week's support tickets, grouped by product area.",
  churn: "Explain the churn trend in the September report.",
  team: "Draft a short team update for Friday's email.",
  search: "When did we decide to drop the annual plan discount?",
};

const REPLY =
  "Here is the short version. Churn rose from 2.1% to 3.4% in September, almost all of it on the monthly " +
  "plan. Two things line up with it: the price change on the 4th, and the slower onboarding emails after the " +
  "template migration. Customers who finished onboarding churned at the same rate as before.";

const actions = (
  <>
    <Button variant="ghost" size="sm">
      Copy
    </Button>
    <Button variant="ghost" size="sm">
      Regenerate
    </Button>
  </>
);

const header = (
  <div style={{ padding: "var(--space-3) var(--space-4)", fontSize: "var(--text-sm)", fontWeight: 600 }}>
    Churn analysis
  </div>
);

interface Message {
  id: number;
  role: "user" | "assistant";
  text: string;
  status?: "done" | "streaming" | "error";
}

/** A conversation that answers every message with a reply that streams in word by word and can be stopped. */
function Live() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [streaming, setStreaming] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval>>(undefined);

  useEffect(() => () => clearInterval(timer.current), []);

  const stop = () => {
    clearInterval(timer.current);
    setStreaming(false);
    setMessages((current) => current.map((message) => ({ ...message, status: "done" })));
  };

  const send = (text: string) => {
    const words = REPLY.split(" ");
    const id = Date.now();
    setMessages((current) => [
      ...current,
      { id, role: "user", text },
      { id: id + 1, role: "assistant", text: "", status: "streaming" },
    ]);
    setStreaming(true);
    let shown = 0;
    // A pause before the first word, like a real model thinking.
    timer.current = setInterval(() => {
      shown += 1;
      if (shown < 8) return;
      const count = shown - 7;
      setMessages((current) =>
        current.map((message) =>
          message.id === id + 1 ? { ...message, text: words.slice(0, count).join(" ") } : message,
        ),
      );
      if (count >= words.length) stop();
    }, 60);
  };

  return (
    <div style={frame}>
      <ChatThread
        header={header}
        empty={
          <ChatWelcome
            title="What should we look into?"
            description="Ask about your workspace's tickets, reports and notes. Answers link to their sources."
            suggestions={SUGGESTIONS}
            onSuggestion={(id) => send(PROMPTS[id] ?? id)}
          />
        }
        composer={
          <Composer
            onSubmit={send}
            busy={streaming}
            onStop={stop}
            onAttach={() => {}}
            placeholder="Ask anything…"
            footer="Answers can be wrong. Check anything important."
          />
        }
      >
        {messages.map((message) =>
          message.role === "user" ? (
            <ChatMessage key={message.id} role="user">
              {message.text}
            </ChatMessage>
          ) : (
            <ChatMessage key={message.id} role="assistant" status={message.status} actions={actions}>
              {message.text && <p>{message.text}</p>}
            </ChatMessage>
          ),
        )}
      </ChatThread>
    </div>
  );
}

function Still({ children, busy, empty }: { children?: ReactNode; busy?: boolean; empty?: ReactNode }) {
  return (
    <div style={frame}>
      <ChatThread
        empty={empty}
        composer={<Composer placeholder="Reply…" busy={busy} onStop={busy ? () => {} : undefined} />}
      >
        {children}
      </ChatThread>
    </div>
  );
}

const question = (
  <ChatMessage role="user" time="09:41" attachments={[{ id: "r", name: "churn-report-q3.pdf", meta: "PDF · 2.4 MB" }]}>
    Why did churn go up in September?
  </ChatMessage>
);

export default defineSpecimen({
  id: "ai-chat",
  title: "AI chat",
  group: "Chat",
  description:
    "A conversation with an assistant: the user's messages in bubbles, the assistant's replies as text with " +
    "their actions, a welcome with ways to start, and the composer. The thread follows new text while the " +
    "reader is at the bottom.",
  order: 76,
  blocks: [
    { kind: "block", title: "Live · send a message or pick a suggestion", render: Live },
    {
      kind: "states",
      states: [
        {
          label: "populated",
          render: () => (
            <Still>
              {question}
              <ChatMessage role="assistant" time="09:41" actions={actions}>
                <p>{REPLY}</p>
              </ChatMessage>
              <ChatMessage role="user" time="09:43">
                Which onboarding emails were slower?
              </ChatMessage>
              <ChatMessage role="assistant" time="09:43" actions={actions}>
                <p>
                  The welcome series. After the migration, emails two and three went out a day later than before, so
                  most new customers met the setup checklist after their first billing reminder.
                </p>
              </ChatMessage>
            </Still>
          ),
        },
        {
          label: "empty",
          render: () => (
            <Still
              empty={
                <ChatWelcome
                  title="What should we look into?"
                  description="Ask about your workspace's tickets, reports and notes."
                  suggestions={SUGGESTIONS}
                />
              }
            />
          ),
        },
        {
          label: "thinking",
          render: () => (
            <Still busy>
              {question}
              <ChatMessage role="assistant" status="streaming" />
            </Still>
          ),
        },
        {
          label: "streaming",
          render: () => (
            <Still busy>
              {question}
              <ChatMessage role="assistant" status="streaming">
                <p>Here is the short version. Churn rose from 2.1% to 3.4% in September, almost all of it on the</p>
              </ChatMessage>
            </Still>
          ),
        },
        {
          label: "error",
          render: () => (
            <Still>
              {question}
              <ChatMessage
                role="assistant"
                status="error"
                error="The connection dropped before the reply was finished."
                onRetry={() => {}}
              >
                <p>Here is the short version. Churn rose from 2.1% to 3.4% in September,</p>
              </ChatMessage>
            </Still>
          ),
        },
        {
          label: "long content",
          render: () => (
            <Still>
              {question}
              <ChatMessage role="assistant" time="09:42" actions={actions}>
                <p>Churn rose for three reasons, in order of how much of the increase they explain:</p>
                <ol>
                  <li>
                    <strong>Price change on 4 September.</strong> Monthly customers on the old Starter price saw a 23%
                    increase; 61% of September's cancellations were among them.
                  </li>
                  <li>
                    <strong>Slower onboarding emails.</strong> Emails two and three went out a day late after the
                    template migration.
                  </li>
                  <li>
                    <strong>Seasonal dip.</strong> September is usually 0.3 points above August.
                  </li>
                </ol>
                <h3>By plan</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Plan</th>
                      <th>August</th>
                      <th>September</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>Starter, monthly</td>
                      <td>2.8%</td>
                      <td>5.1%</td>
                    </tr>
                    <tr>
                      <td>Team, monthly</td>
                      <td>1.9%</td>
                      <td>2.2%</td>
                    </tr>
                    <tr>
                      <td>Annual plans</td>
                      <td>0.6%</td>
                      <td>0.6%</td>
                    </tr>
                  </tbody>
                </table>
                <p>
                  To check this yourself, filter cancellations by <code>plan_interval</code> and{" "}
                  <code>price_version</code>:
                </p>
                <pre>
                  <code>{`select plan, count(*) from cancellations\nwhere cancelled_at >= '2026-09-01'\ngroup by plan;`}</code>
                </pre>
              </ChatMessage>
            </Still>
          ),
        },
      ],
    },
  ],
});

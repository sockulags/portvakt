import { Children, useEffect, useRef, useState, type ReactNode } from "react";
import { Avatar, Button } from "../components/index";
import type { ComposerAttachment } from "./Composer";
import { Icon, type IconName } from "./icons";
import styles from "./Chat.module.css";

export interface ChatThreadProps {
  /** The messages, oldest first: usually ChatMessage elements. */
  children?: ReactNode;
  /** Usually a Composer, kept at the bottom. */
  composer: ReactNode;
  /** Shown while there are no messages, usually a ChatWelcome. */
  empty?: ReactNode;
  /** A bar above the messages: the conversation's title and its actions. */
  header?: ReactNode;
}

/** Distance from the bottom, in pixels, within which the thread keeps following new content. */
const FOLLOW = 48;

function scrollToEnd(element: HTMLElement | null) {
  if (element) element.scrollTop = element.scrollHeight;
}

/**
 * A conversation: messages that scroll, a composer at the bottom. It fills its container's height and follows
 * new content while the reader is at the bottom; scrolled up, it stays put and offers a way back.
 */
export function ChatThread({ children, composer, empty, header }: ChatThreadProps) {
  const scroller = useRef<HTMLDivElement>(null);
  const content = useRef<HTMLDivElement>(null);
  const following = useRef(true);
  const [away, setAway] = useState(false);
  const hasMessages = Children.count(children) > 0;

  useEffect(() => {
    const element = content.current;
    if (!element) return;
    const observer = new ResizeObserver(() => {
      if (following.current) scrollToEnd(scroller.current);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  return (
    <div className={styles.thread} data-ds="chat-thread">
      {header && <div className={styles.header}>{header}</div>}
      <div
        ref={scroller}
        className={styles.scroller}
        onScroll={(event) => {
          const element = event.currentTarget;
          following.current = element.scrollHeight - element.scrollTop - element.clientHeight < FOLLOW;
          setAway(!following.current);
        }}
      >
        <div ref={content} className={styles.column}>
          {hasMessages ? (
            <div className={styles.messages} role="log" aria-label="Conversation">
              {children}
            </div>
          ) : (
            empty
          )}
        </div>
      </div>
      <div className={styles.bottom}>
        {away && hasMessages && (
          <button
            type="button"
            className={styles.latest}
            aria-label="Jump to the latest message"
            onClick={() => {
              following.current = true;
              setAway(false);
              scrollToEnd(scroller.current);
            }}
          >
            <Icon name="arrow-down" size={14} />
          </button>
        )}
        <div className={styles.column}>{composer}</div>
      </div>
    </div>
  );
}

export interface ChatMessageProps {
  role: "user" | "assistant";
  /** The text, or richer content: paragraphs, lists, code and tables are styled. */
  children?: ReactNode;
  /** Shown above assistant messages; defaults to "Assistant". */
  author?: string;
  /** Replaces the assistant's avatar. */
  avatar?: ReactNode;
  time?: string;
  /** `streaming` while the reply arrives (typing dots until there is text), `error` when it failed. */
  status?: "done" | "streaming" | "error";
  /** What went wrong, with status `error`. */
  error?: string;
  /** Shows a Retry button with the error. */
  onRetry?: () => void;
  /** Controls under a finished message, such as Copy and Regenerate. */
  actions?: ReactNode;
  /** Files sent with a user message. */
  attachments?: ComposerAttachment[];
}

/** One message: the user's in a bubble on the right, the assistant's as full-width text with its avatar. */
export function ChatMessage({
  role,
  children,
  author = "Assistant",
  avatar,
  time,
  status = "done",
  error,
  onRetry,
  actions,
  attachments = [],
}: ChatMessageProps) {
  const files = attachments.length > 0 && (
    <ul className={styles.files} aria-label="Attachments">
      {attachments.map((file) => (
        <li key={file.id} className={styles.file}>
          <Icon name="file" size={14} />
          <span className={styles.fileName}>{file.name}</span>
          {file.meta && <span className={styles.fileMeta}>{file.meta}</span>}
        </li>
      ))}
    </ul>
  );

  if (role === "user") {
    return (
      <article className={styles.user} data-ds="chat-message" data-role="user" aria-label="You">
        {files}
        {children && <div className={styles.bubble}>{children}</div>}
        {time && <span className={styles.time}>{time}</span>}
      </article>
    );
  }

  const empty = Children.toArray(children).every((child) => child === "");
  return (
    <article
      className={styles.assistant}
      data-ds="chat-message"
      data-role="assistant"
      data-status={status}
      aria-label={author}
      aria-busy={status === "streaming" || undefined}
    >
      <span className={styles.avatar}>{avatar ?? <Avatar initials={initialsOf(author)} />}</span>
      <div className={styles.body}>
        <p className={styles.meta}>
          <span className={styles.author}>{author}</span>
          {time && <span className={styles.time}>{time}</span>}
        </p>
        {status === "streaming" && empty ? (
          <span className={styles.typing} role="status" aria-label={`${author} is writing`}>
            <span />
            <span />
            <span />
          </span>
        ) : (
          !empty && (
            <div className={styles.content} data-streaming={status === "streaming" || undefined}>
              {children}
            </div>
          )
        )}
        {status === "error" && (
          <div className={styles.error} role="alert">
            <Icon name="alert" size={14} />
            <span>{error ?? "The reply could not be finished."}</span>
            {onRetry && (
              <Button variant="outline" size="sm" onClick={onRetry}>
                Retry
              </Button>
            )}
          </div>
        )}
        {status === "done" && actions && <div className={styles.actions}>{actions}</div>}
      </div>
    </article>
  );
}

function initialsOf(name: string): string {
  const words = name.trim().split(/\s+/);
  return ((words[0]?.[0] ?? "") + (words[1]?.[0] ?? words[0]?.[1] ?? "")).toUpperCase();
}

export interface ChatSuggestion {
  id: string;
  label: string;
  description?: string;
  icon?: IconName;
}

export interface ChatWelcomeProps {
  title: string;
  description?: string;
  /** Ways to start, usually three or four. */
  suggestions?: ChatSuggestion[];
  onSuggestion?: (id: string) => void;
}

/** The start of a conversation: what the assistant is for, and a few ways to begin. */
export function ChatWelcome({ title, description, suggestions = [], onSuggestion }: ChatWelcomeProps) {
  return (
    <div className={styles.welcome} data-ds="chat-welcome">
      <h2 className={styles.welcomeTitle}>{title}</h2>
      {description && <p className={styles.welcomeText}>{description}</p>}
      {suggestions.length > 0 && (
        <ul className={styles.suggestions}>
          {suggestions.map((suggestion) => (
            <li key={suggestion.id}>
              <button type="button" className={styles.suggestion} onClick={() => onSuggestion?.(suggestion.id)}>
                {suggestion.icon && (
                  <span className={styles.suggestionIcon}>
                    <Icon name={suggestion.icon} size={16} />
                  </span>
                )}
                <span className={styles.suggestionLabel}>{suggestion.label}</span>
                {suggestion.description && <span className={styles.suggestionText}>{suggestion.description}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

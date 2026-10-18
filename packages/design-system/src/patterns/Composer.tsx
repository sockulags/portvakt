import { useLayoutEffect, useRef, useState, type CSSProperties, type KeyboardEvent, type ReactNode } from "react";
import { Button, Spinner } from "../components/index";
import { Icon } from "./icons";
import styles from "./Composer.module.css";

export interface ComposerAttachment {
  id: string;
  name: string;
  /** Type and size, such as "PDF · 2.4 MB". */
  meta?: string;
  /** Still uploading: shows a spinner and holds Send back until it is done. */
  uploading?: boolean;
}

export interface ComposerProps {
  /** The text, for a controlled composer. Leave it out and the composer keeps its own. */
  value?: string;
  onValueChange?: (value: string) => void;
  /** Enter or the Send button. A composer that keeps its own text clears it afterwards. */
  onSubmit?: (text: string) => void;
  placeholder?: string;
  /** Accessible name of the text field; defaults to the placeholder. */
  label?: string;
  attachments?: ComposerAttachment[];
  /** Shows the attach button. */
  onAttach?: () => void;
  onRemoveAttachment?: (id: string) => void;
  /** A reply is on its way: Send becomes Stop (with `onStop`) and Enter no longer sends. */
  busy?: boolean;
  onStop?: () => void;
  disabled?: boolean;
  /** Controls at the start of the toolbar, such as a mode picker. */
  tools?: ReactNode;
  /** A line under the composer: a disclaimer, a limit or a hint. */
  footer?: ReactNode;
  /** Rows the field grows to before it scrolls. */
  maxRows?: number;
  autoFocus?: boolean;
  /** Pins the focus ring, for the gallery. */
  force?: "focus";
}

/** Where a message is written: a text field that grows with its content, attachments, and Send or Stop. */
export function Composer({
  value,
  onValueChange,
  onSubmit,
  placeholder = "Write a message…",
  label,
  attachments = [],
  onAttach,
  onRemoveAttachment,
  busy = false,
  onStop,
  disabled = false,
  tools,
  footer,
  maxRows = 8,
  autoFocus,
  force,
}: ComposerProps) {
  const [own, setOwn] = useState("");
  const text = value ?? own;
  const field = useRef<HTMLTextAreaElement>(null);

  // Grow with the content up to maxRows (capped in CSS), then scroll.
  useLayoutEffect(() => {
    const element = field.current;
    if (!element) return;
    element.style.height = "auto";
    element.style.height = `${element.scrollHeight}px`;
  }, [text, maxRows]);

  const change = (next: string) => {
    if (value === undefined) setOwn(next);
    onValueChange?.(next);
  };

  const uploading = attachments.some((attachment) => attachment.uploading);
  const canSend = !disabled && !busy && !uploading && (text.trim() !== "" || attachments.length > 0);

  const submit = () => {
    if (!canSend) return;
    onSubmit?.(text);
    if (value === undefined) setOwn("");
  };

  const keyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key !== "Enter" || event.shiftKey || event.nativeEvent.isComposing) return;
    event.preventDefault();
    submit();
  };

  return (
    <div className={styles.root} data-ds="composer">
      <div
        className={styles.composer}
        data-busy={busy || undefined}
        data-disabled={disabled || undefined}
        data-force={force}
        style={{ "--composer-rows": maxRows } as CSSProperties}
        onMouseDown={(event) => {
          // A click on the padding or the empty toolbar puts the caret in the field.
          if ((event.target as HTMLElement).closest("button, a, input, select, textarea, label, li")) return;
          event.preventDefault();
          field.current?.focus();
        }}
      >
        {attachments.length > 0 && (
          <ul className={styles.attachments} aria-label="Attachments">
            {attachments.map((attachment) => (
              <li key={attachment.id} className={styles.attachment} data-uploading={attachment.uploading || undefined}>
                <span className={styles.fileIcon}>
                  {attachment.uploading ? <Spinner size={14} /> : <Icon name="file" size={14} />}
                </span>
                <span className={styles.fileText}>
                  <span className={styles.fileName}>{attachment.name}</span>
                  {attachment.meta && <span className={styles.fileMeta}>{attachment.meta}</span>}
                </span>
                {onRemoveAttachment && (
                  <button
                    type="button"
                    className={styles.remove}
                    aria-label={`Remove ${attachment.name}`}
                    disabled={disabled}
                    onClick={() => onRemoveAttachment(attachment.id)}
                  >
                    <Icon name="close" size={12} />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        <textarea
          ref={field}
          className={styles.field}
          rows={1}
          value={text}
          placeholder={placeholder}
          aria-label={label ?? placeholder}
          disabled={disabled}
          autoFocus={autoFocus}
          onChange={(event) => change(event.target.value)}
          onKeyDown={keyDown}
        />
        <div className={styles.toolbar}>
          {onAttach && (
            <Button
              variant="ghost"
              size="sm"
              className={styles.iconButton}
              aria-label="Attach files"
              disabled={disabled}
              onClick={onAttach}
            >
              <Icon name="plus" />
            </Button>
          )}
          {tools}
          <span className={styles.spacer} />
          {busy && onStop ? (
            <Button variant="secondary" size="sm" className={styles.iconButton} aria-label="Stop" onClick={onStop}>
              <span className={styles.stop} />
            </Button>
          ) : (
            <Button
              size="sm"
              className={styles.iconButton}
              aria-label="Send"
              disabled={!canSend}
              loading={busy}
              onClick={submit}
            >
              <Icon name="arrow-up" />
            </Button>
          )}
        </div>
      </div>
      {footer && <p className={styles.footer}>{footer}</p>}
    </div>
  );
}

/** Pseudo-states the gallery can pin on a component so every state is visible at once. */
export type ForcedState = "hover" | "focus" | "active";

export function cx(...names: (string | false | null | undefined)[]): string {
  return names.filter(Boolean).join(" ");
}

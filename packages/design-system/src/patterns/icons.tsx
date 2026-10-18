import type { SVGProps } from "react";

/** A small stroke icon set for the patterns. Icons inherit colour from the text around them. */
const PATHS = {
  home: <path d="M2.5 7.5 8 3l5.5 4.5M4 6.5V13h3V9.5h2V13h3V6.5" />,
  inbox: <path d="M2.5 9.5 4 3.5h8l1.5 6M2.5 9.5V13h11V9.5h-3.5a2 2 0 0 1-4 0Z" />,
  chart: <path d="M2.5 13.5h11M4.5 11V8M8 11V4.5M11.5 11V6.5" />,
  users: (
    <>
      <circle cx="6" cy="5.5" r="2.5" />
      <path d="M1.5 13a4.5 4.5 0 0 1 9 0M10.5 3.2a2.5 2.5 0 0 1 0 4.6M12 9.3a4.5 4.5 0 0 1 2.5 3.7" />
    </>
  ),
  settings: (
    <>
      <circle cx="8" cy="8" r="2" />
      <path d="M8 1.75v1.5M8 12.75v1.5M14.25 8h-1.5M3.25 8h-1.5M12.4 3.6l-1.06 1.06M4.66 11.34 3.6 12.4M12.4 12.4l-1.06-1.06M4.66 4.66 3.6 3.6" />
    </>
  ),
  folder: <path d="M1.75 4.25a1 1 0 0 1 1-1h3.5l1.5 1.5h5.5a1 1 0 0 1 1 1v6.5a1 1 0 0 1-1 1h-10.5a1 1 0 0 1-1-1Z" />,
  file: <path d="M4 1.75h5l3 3v9.5H4ZM9 1.75v3h3" />,
  search: (
    <>
      <circle cx="7" cy="7" r="4.25" />
      <path d="m10.25 10.25 3.5 3.5" />
    </>
  ),
  bell: <path d="M4 11V7a4 4 0 0 1 8 0v4l1.25 1.5H2.75ZM6.5 14h3" />,
  plus: <path d="M8 3v10M3 8h10" />,
  menu: <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />,
  close: <path d="m4 4 8 8M12 4l-8 8" />,
  "chevron-left": <path d="M10 3.5 5.5 8l4.5 4.5" />,
  "chevron-right": <path d="M6 3.5 10.5 8 6 12.5" />,
  "chevron-down": <path d="M3.5 6 8 10.5 12.5 6" />,
  sort: <path d="M5 6 8 3l3 3M5 10l3 3 3-3" />,
  "sort-up": <path d="M5 7 8 4l3 3M8 4v8" />,
  "sort-down": <path d="M5 9l3 3 3-3M8 12V4" />,
  "arrow-up": <path d="M8 13V3M4 7l4-4 4 4" />,
  "arrow-down": <path d="M8 3v10M4 9l4 4 4-4" />,
  minus: <path d="M3 8h10" />,
  alert: <path d="M8 2.5 14 13H2ZM8 6.5v3M8 11.25v.01" />,
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 16, ...rest }: { name: IconName; size?: number } & Omit<SVGProps<SVGSVGElement>, "name">) {
  return (
    <svg
      viewBox="0 0 16 16"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.4}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      focusable={false}
      {...rest}
    >
      {PATHS[name]}
    </svg>
  );
}

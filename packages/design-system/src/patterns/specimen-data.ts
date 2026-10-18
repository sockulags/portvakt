// Sample content shared by the pattern specimens. Not part of any pattern's API.
import type { SidebarNavSection } from "./SidebarNav";

export interface Member {
  id: string;
  name: string;
  email: string;
  role: "Owner" | "Admin" | "Editor" | "Viewer";
  status: "Active" | "Invited" | "Suspended";
  projects: number;
  lastActive: string;
}

export const MEMBERS: Member[] = [
  { id: "m1", name: "Ada Lovelace", email: "ada@analytical.dev", role: "Owner", status: "Active", projects: 12, lastActive: "2 min ago" },
  { id: "m2", name: "Grace Hopper", email: "grace@cobol.org", role: "Admin", status: "Active", projects: 9, lastActive: "1 h ago" },
  { id: "m3", name: "Alan Turing", email: "alan@bletchley.uk", role: "Editor", status: "Invited", projects: 0, lastActive: "—" },
  { id: "m4", name: "Katherine Johnson", email: "katherine@nasa.gov", role: "Editor", status: "Active", projects: 7, lastActive: "Yesterday" },
  { id: "m5", name: "Edsger Dijkstra", email: "edsger@tue.nl", role: "Viewer", status: "Suspended", projects: 3, lastActive: "3 weeks ago" },
  { id: "m6", name: "Margaret Hamilton", email: "margaret@apollo.space", role: "Admin", status: "Active", projects: 15, lastActive: "5 min ago" },
  { id: "m7", name: "Linus Torvalds", email: "linus@kernel.org", role: "Viewer", status: "Active", projects: 2, lastActive: "Today" },
];

export const NAV_LINKS = [
  { id: "overview", label: "Overview" },
  { id: "projects", label: "Projects" },
  { id: "team", label: "Team" },
  { id: "reports", label: "Reports" },
];

export const SIDEBAR_SECTIONS: SidebarNavSection[] = [
  {
    items: [
      { id: "home", label: "Home", icon: "home" },
      { id: "inbox", label: "Inbox", icon: "inbox", badge: 4 },
      { id: "projects", label: "Projects", icon: "folder" },
      { id: "reports", label: "Reports", icon: "chart" },
    ],
  },
  {
    title: "Workspace",
    items: [
      { id: "team", label: "Team", icon: "users" },
      { id: "docs", label: "Documents", icon: "file", badge: 12 },
      { id: "settings", label: "Settings", icon: "settings" },
    ],
  },
];

export const initials = (name: string) =>
  name
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

import { Button } from "../components/index";
import { defineSpecimen } from "../components/specimen";
import { EmptyState } from "./EmptyState";
import { Icon } from "./icons";

const card = {
  width: "100%",
  border: "var(--border-thin) dashed var(--color-border-strong)",
  borderRadius: "var(--radius-lg)",
} as const;

export default defineSpecimen({
  id: "empty-states",
  title: "Empty states",
  group: "Feedback",
  description: "What to show when there is nothing to show: a first visit, a search with no results, or a failure.",
  order: 70,
  blocks: [
    {
      kind: "grid",
      min: 260,
      items: [
        {
          label: "first use",
          render: () => (
            <div style={card}>
              <EmptyState
                icon="folder"
                title="No projects yet"
                description="Projects keep tasks, files and people together. Start with one for your next launch."
                actions={
                  <Button>
                    <Icon name="plus" size={14} />
                    Create project
                  </Button>
                }
              />
            </div>
          ),
        },
        {
          label: "no results",
          render: () => (
            <div style={card}>
              <EmptyState
                icon="search"
                title="Nothing matches “invoice 2019”"
                description="Try fewer words or search all workspaces."
                actions={<Button variant="secondary">Search everywhere</Button>}
              />
            </div>
          ),
        },
        {
          label: "error",
          render: () => (
            <div style={card}>
              <EmptyState
                icon="alert"
                tone="danger"
                title="Couldn't load reports"
                description="The reporting service didn't answer. Your data is safe."
                actions={<Button variant="secondary">Try again</Button>}
              />
            </div>
          ),
        },
      ],
    },
  ],
});

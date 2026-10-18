import { defineSpecimen } from "../components/specimen";
import { StatCard } from "./StatCard";

export default defineSpecimen({
  id: "stats",
  title: "Stat cards",
  group: "Data",
  description: "Key numbers with their change and recent trend. Colour follows meaning: fewer errors is good news.",
  order: 50,
  blocks: [
    {
      kind: "grid",
      min: 220,
      items: [
        {
          label: "rising, good",
          render: () => (
            <StatCard
              label="Monthly revenue"
              value="€48,290"
              delta={{ value: "12.4%", direction: "up" }}
              hint="vs last month"
              trend={[31, 34, 33, 38, 41, 40, 44, 48]}
            />
          ),
        },
        {
          label: "falling, good",
          render: () => (
            <StatCard
              label="Error rate"
              value="0.42%"
              delta={{ value: "0.18 pts", direction: "down", good: true }}
              hint="last 7 days"
              trend={[0.9, 0.8, 0.85, 0.7, 0.6, 0.55, 0.42]}
            />
          ),
        },
        {
          label: "falling, bad",
          render: () => (
            <StatCard
              label="Active users"
              value="8,312"
              delta={{ value: "3.1%", direction: "down" }}
              hint="vs last week"
              trend={[9.1, 9.0, 8.8, 8.9, 8.6, 8.4, 8.3]}
            />
          ),
        },
        { label: "flat", render: () => <StatCard label="Open tickets" value="27" delta={{ value: "0", direction: "flat" }} hint="no change" /> },
        { label: "loading", render: () => <StatCard label="Conversion" value="" loading /> },
      ],
    },
  ],
});

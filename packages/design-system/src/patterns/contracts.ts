/**
 * Contracts for the patterns this design system adds beyond the Basis baseline
 * (.basis/pattern-contracts.ts covers Navbar, DataTable and the rest of the
 * starter set).
 *
 * Every export of index.ts needs a contract, either in the baseline or here, and
 * Basis type-checks the patterns against both after every change. A contract is
 * the pattern's public API, which views and other patterns build on: declare its
 * props here, let the pattern accept them, and change an existing entry only
 * when the API is meant to change.
 *
 * Import only from "react" and ./icons.tsx. Example:
 *
 *   import type { ComponentType } from "react";
 *
 *   export interface PricingTableProps {
 *     plans: { name: string; price: string; features: string[] }[];
 *     highlighted?: string;
 *   }
 *
 *   export interface AddedPatternContracts {
 *     PricingTable: ComponentType<PricingTableProps>;
 *   }
 */
export interface AddedPatternContracts {}

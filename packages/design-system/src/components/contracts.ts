/**
 * Contracts for the components this design system adds beyond the Basis baseline
 * (.basis/contracts.ts covers Button, Field, Tabs and the rest of the starter set).
 *
 * Every export of index.ts needs a contract, either in the baseline or here, and
 * Basis type-checks the components against both after every change. A contract is
 * the component's public API: declare its props here, let the component accept
 * them, and change an existing entry only when the API is meant to change.
 *
 * Import only from "react". Example:
 *
 *   import type { ComponentType } from "react";
 *
 *   export interface RatingProps {
 *     value: number;
 *     max?: number;
 *     onChange?: (value: number) => void;
 *   }
 *
 *   export interface AddedContracts {
 *     Rating: ComponentType<RatingProps>;
 *   }
 */
export interface AddedContracts {}

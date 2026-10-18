import type { MasterKeys } from "../config/index.js";
import { BlindIndex } from "./blind-index.js";
import { SecretBox } from "./envelope.js";

/** Everything derived from the master keys: envelope encryption and the blind index. */
export interface KeyRing {
  readonly secrets: SecretBox;
  readonly index: BlindIndex;
}

export function createKeyRing(masterKeys: MasterKeys): KeyRing {
  return {
    secrets: SecretBox.fromMasterKeys(masterKeys),
    index: BlindIndex.fromMasterKeys(masterKeys),
  };
}

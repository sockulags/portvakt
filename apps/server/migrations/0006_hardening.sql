-- Production hardening (M8). See docs/plan.md and CLAUDE.md ("Signing key transitions").
--
-- * signing_keys.activate_at: a manual rotation without `emergency` publishes the new key at
--   once and schedules its activation (KEY_MANUAL_PUBLISH_AHEAD later); the rotation job
--   activates it once the time has come. Only a `next` key carries a schedule; activation (or
--   discarding the key) clears it. Keys from the scheduled rotation keep using created_at plus
--   KEY_PUBLISH_AHEAD.

ALTER TABLE signing_keys ADD COLUMN activate_at timestamptz;

ALTER TABLE signing_keys
  ADD CONSTRAINT signing_keys_activate_at_next CHECK (activate_at IS NULL OR state = 'next');

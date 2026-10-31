-- A new-User Invite may preset the abroad permission (ADR 0014).
ALTER TABLE invites ADD COLUMN abroad INTEGER NOT NULL DEFAULT 0;

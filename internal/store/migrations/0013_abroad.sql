-- Abroad Devices (ADR 0014): a per-User permission, a kind fixed on each
-- Device, the built-in Abroad Rule, and the Abroad Bridge Address's record.
ALTER TABLE users ADD COLUMN abroad INTEGER NOT NULL DEFAULT 0;   -- may hold Abroad Devices
ALTER TABLE devices ADD COLUMN abroad INTEGER NOT NULL DEFAULT 0; -- its address is in 10.77.128.0/17

-- The Abroad Rule matches its Devices by source, ahead of every Rule, and
-- sends everything, the Everything set, to an Exit tagged IR. It is locked.
ALTER TABLE rules ADD COLUMN source TEXT; -- NULL for a destination Rule
INSERT INTO rules (name, priority, set_id, required_tags, fallback, builtin, source)
    VALUES ('Abroad', 0, 2, '["IR"]', 'drop', 1, '10.77.128.0/17');

CREATE TABLE abroad_address (
    node_id   TEXT PRIMARY KEY,
    joined_at INTEGER NOT NULL
);

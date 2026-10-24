-- The Bridge Address (ADR 0011) replaces the Endpoint Slots: the Bridges
-- its record holds, and since when. Bridges holding a slot start out in it.
CREATE TABLE bridge_address (
    node_id   TEXT PRIMARY KEY,
    joined_at INTEGER NOT NULL
);
INSERT INTO bridge_address (node_id, joined_at)
    SELECT node_id, min(changed_at) FROM endpoint_slots GROUP BY node_id;
DROP TABLE endpoint_slots;

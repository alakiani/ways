-- Unlisted Bridges (ADR 0015): an Admin took the domestic Bridge out of the
-- Bridge Address; it stays out until listed again.
ALTER TABLE nodes ADD COLUMN unlisted INTEGER NOT NULL DEFAULT 0;

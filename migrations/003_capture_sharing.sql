-- Per-capture sharing: captures are private to their owner (created_by) by
-- default; the owner (or an admin) can flip `shared` to make it visible to
-- every user. Captures with no owner (created_by IS NULL — e.g. Wireshark
-- SSH remote-capture pushes, which have no pktPCAP user context at all)
-- predate this feature and stay visible to everyone regardless of `shared`,
-- same as before it existed.
ALTER TABLE captures ADD COLUMN shared INTEGER NOT NULL DEFAULT 0;

-- Migration 039: Persist Auth Center user position metadata for directory views.

ALTER TABLE users ADD COLUMN position TEXT;
ALTER TABLE users ADD COLUMN position_sort INTEGER;

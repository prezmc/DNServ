-- One row per weekly summary. No IP address, no install ID: report_id is
-- random and new every week, only so a retry isn't counted twice.
CREATE TABLE IF NOT EXISTS reports (
  report_id       TEXT PRIMARY KEY,
  week            TEXT NOT NULL,
  received        TEXT NOT NULL, -- day only, YYYY-MM-DD
  country         TEXT,
  schema          INTEGER NOT NULL,
  version         TEXT,
  channel         TEXT,
  arch            TEXT,
  servers         INTEGER,
  witnesses       INTEGER,
  upstream_mode   TEXT,
  devices         TEXT,
  lookups_per_day TEXT,
  answer_ms_p50   REAL,
  answer_ms_p95   REAL,
  cache_hit_pct   REAL,
  blocked_pct     REAL,
  failed_pct      REAL,
  lists           INTEGER,
  features        TEXT -- JSON array
);
CREATE INDEX IF NOT EXISTS reports_week ON reports (week);

-- Weekly totals, kept after the reports themselves are deleted (90 days).
CREATE TABLE IF NOT EXISTS weeks (
  week   TEXT PRIMARY KEY,
  totals TEXT NOT NULL -- JSON, as served by /v1/totals
);

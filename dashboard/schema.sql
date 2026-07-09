-- BLT Secure fleet dashboard — D1 schema.
-- Apply with: wrangler d1 execute blt-secure-fleet --file=schema.sql

CREATE TABLE IF NOT EXISTS sites (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash  TEXT NOT NULL UNIQUE,   -- sha256(site token); the raw token is never stored
  site_url    TEXT,
  name        TEXT,
  enrolled_at INTEGER,
  last_seen   INTEGER
);

-- One latest snapshot per site (site_id is the primary key → upsert on report).
CREATE TABLE IF NOT EXISTS snapshots (
  site_id     INTEGER PRIMARY KEY,
  reported_at INTEGER,
  payload     TEXT,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER,
  ts      INTEGER,
  type    TEXT,
  count   INTEGER,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_site ON events (site_id, ts);

CREATE TABLE IF NOT EXISTS commands (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id      INTEGER,
  created_at   INTEGER,
  command      TEXT,
  params       TEXT,
  status       TEXT DEFAULT 'pending',   -- pending | delivered | done
  delivered_at INTEGER,
  FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_commands_site ON commands (site_id, status);

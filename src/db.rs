use rusqlite::Connection;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS splitters (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    base_currency TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    splitter_id INTEGER NOT NULL REFERENCES splitters(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS persons (
    id          INTEGER PRIMARY KEY,
    splitter_id INTEGER NOT NULL REFERENCES splitters(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    UNIQUE (splitter_id, name)
);

CREATE TABLE IF NOT EXISTS person_groups (
    id          INTEGER PRIMARY KEY,
    splitter_id INTEGER NOT NULL REFERENCES splitters(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    UNIQUE (splitter_id, name)
);

CREATE TABLE IF NOT EXISTS person_group_members (
    group_id  INTEGER NOT NULL REFERENCES person_groups(id) ON DELETE CASCADE,
    person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, person_id)
);

CREATE TABLE IF NOT EXISTS payment_methods (
    id          INTEGER PRIMARY KEY,
    splitter_id INTEGER NOT NULL REFERENCES splitters(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    UNIQUE (splitter_id, name)
);

CREATE TABLE IF NOT EXISTS payment_method_members (
    method_id INTEGER NOT NULL REFERENCES payment_methods(id) ON DELETE CASCADE,
    person_id INTEGER NOT NULL REFERENCES persons(id) ON DELETE CASCADE,
    PRIMARY KEY (method_id, person_id)
);

-- rate = value of 1 unit of `code` expressed in the splitter's base currency.
CREATE TABLE IF NOT EXISTS rates (
    splitter_id INTEGER NOT NULL REFERENCES splitters(id) ON DELETE CASCADE,
    code        TEXT NOT NULL,
    rate        REAL NOT NULL,
    PRIMARY KEY (splitter_id, code)
);

CREATE TABLE IF NOT EXISTS bills (
    id          INTEGER PRIMARY KEY,
    splitter_id INTEGER NOT NULL REFERENCES splitters(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    currency    TEXT NOT NULL,
    date        TEXT,
    split_mode  TEXT NOT NULL CHECK (split_mode IN ('equal', 'shares', 'exact')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Amounts are integer minor units (cents) of the bill's currency.
CREATE TABLE IF NOT EXISTS bill_payers (
    bill_id   INTEGER NOT NULL REFERENCES bills(id) ON DELETE CASCADE,
    person_id INTEGER NOT NULL REFERENCES persons(id),
    amount    INTEGER NOT NULL,
    PRIMARY KEY (bill_id, person_id)
);

-- `weight` is what the user entered (1 for equal, share count, or cents for
-- exact); `owed` is the resulting amount in cents, computed at write time.
CREATE TABLE IF NOT EXISTS bill_shares (
    bill_id   INTEGER NOT NULL REFERENCES bills(id) ON DELETE CASCADE,
    person_id INTEGER NOT NULL REFERENCES persons(id),
    weight    REAL NOT NULL,
    owed      INTEGER NOT NULL,
    PRIMARY KEY (bill_id, person_id)
);
"#;

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

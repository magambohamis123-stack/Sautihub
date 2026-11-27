PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS shows (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    category TEXT NOT NULL DEFAULT 'Tamthilia',
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    r2_key TEXT NOT NULL UNIQUE,
    owner_id TEXT NOT NULL,
    created_at TEXT NOT NULL,

    FOREIGN KEY (owner_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_shows_created_at
ON shows(created_at);

CREATE INDEX IF NOT EXISTS idx_shows_owner_id
ON shows(owner_id);

CREATE INDEX IF NOT EXISTS idx_shows_category
ON shows(category);

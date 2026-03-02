package cache

import "database/sql"

const schemaVersion = 1

var migrations = []string{
	// Version 1: Initial schema
	`CREATE TABLE IF NOT EXISTS cve_cache (
		cve_id     TEXT PRIMARY KEY,
		data       BLOB NOT NULL,
		source     TEXT NOT NULL,
		fetched_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS kev_cache (
		id              INTEGER PRIMARY KEY CHECK (id = 1),
		catalog_version TEXT NOT NULL,
		data            BLOB NOT NULL,
		fetched_at      INTEGER NOT NULL,
		expires_at      INTEGER NOT NULL,
		etag            TEXT
	);

	CREATE TABLE IF NOT EXISTS epss_cache (
		cve_id     TEXT PRIMARY KEY,
		data       BLOB NOT NULL,
		fetched_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS advisory_cache (
		advisory_id TEXT PRIMARY KEY,
		data        BLOB NOT NULL,
		source      TEXT NOT NULL,
		fetched_at  INTEGER NOT NULL,
		expires_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS cache_metadata (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	INSERT OR REPLACE INTO cache_metadata (key, value) VALUES ('schema_version', '1');`,
}

// migrate runs all pending migrations.
func migrate(db *sql.DB) error {
	// Check current schema version
	var currentVersion int
	row := db.QueryRow("SELECT value FROM cache_metadata WHERE key = 'schema_version'")
	if err := row.Scan(&currentVersion); err != nil {
		// Table doesn't exist yet, start from 0
		currentVersion = 0
	}

	// Run pending migrations
	for i := currentVersion; i < len(migrations); i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			return err
		}
	}

	return nil
}

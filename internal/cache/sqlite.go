package cache

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteCache implements Cache using a local SQLite database.
type SQLiteCache struct {
	db *sql.DB
}

// NewSQLite creates a new SQLiteCache at the given directory.
// It creates the directory and database file if they don't exist.
func NewSQLite(cacheDir string) (*SQLiteCache, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}

	dbPath := filepath.Join(cacheDir, "cache.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening cache database: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating cache database: %w", err)
	}

	return &SQLiteCache{db: db}, nil
}

func (c *SQLiteCache) GetCVE(ctx context.Context, cveID string) (*Entry, error) {
	var data []byte
	var source string
	var fetchedAt, expiresAt int64

	err := c.db.QueryRowContext(ctx,
		"SELECT data, source, fetched_at, expires_at FROM cve_cache WHERE cve_id = ?",
		cveID,
	).Scan(&data, &source, &fetchedAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	decompressed, err := decompress(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing cached CVE data: %w", err)
	}

	return &Entry{
		Data:      decompressed,
		Source:    source,
		FetchedAt: time.Unix(fetchedAt, 0),
		ExpiresAt: time.Unix(expiresAt, 0),
	}, nil
}

func (c *SQLiteCache) SetCVE(ctx context.Context, cveID string, data []byte, source string, ttl time.Duration) error {
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("compressing CVE data: %w", err)
	}

	now := time.Now()
	_, err = c.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO cve_cache (cve_id, data, source, fetched_at, expires_at) VALUES (?, ?, ?, ?, ?)",
		cveID, compressed, source, now.Unix(), now.Add(ttl).Unix(),
	)
	return err
}

func (c *SQLiteCache) GetKEV(ctx context.Context) (*Entry, error) {
	var data []byte
	var catalogVersion, etag string
	var fetchedAt, expiresAt int64

	err := c.db.QueryRowContext(ctx,
		"SELECT data, catalog_version, fetched_at, expires_at, COALESCE(etag, '') FROM kev_cache WHERE id = 1",
	).Scan(&data, &catalogVersion, &fetchedAt, &expiresAt, &etag)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	decompressed, err := decompress(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing cached KEV data: %w", err)
	}

	return &Entry{
		Data:      decompressed,
		Source:    catalogVersion,
		FetchedAt: time.Unix(fetchedAt, 0),
		ExpiresAt: time.Unix(expiresAt, 0),
		ETag:      etag,
	}, nil
}

func (c *SQLiteCache) SetKEV(ctx context.Context, data []byte, catalogVersion string, etag string, ttl time.Duration) error {
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("compressing KEV data: %w", err)
	}

	now := time.Now()
	_, err = c.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO kev_cache (id, catalog_version, data, fetched_at, expires_at, etag) VALUES (1, ?, ?, ?, ?, ?)",
		catalogVersion, compressed, now.Unix(), now.Add(ttl).Unix(), etag,
	)
	return err
}

func (c *SQLiteCache) GetEPSS(ctx context.Context, cveID string) (*Entry, error) {
	var data []byte
	var fetchedAt, expiresAt int64

	err := c.db.QueryRowContext(ctx,
		"SELECT data, fetched_at, expires_at FROM epss_cache WHERE cve_id = ?",
		cveID,
	).Scan(&data, &fetchedAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	decompressed, err := decompress(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing cached EPSS data: %w", err)
	}

	return &Entry{
		Data:      decompressed,
		Source:    "epss",
		FetchedAt: time.Unix(fetchedAt, 0),
		ExpiresAt: time.Unix(expiresAt, 0),
	}, nil
}

func (c *SQLiteCache) SetEPSS(ctx context.Context, cveID string, data []byte, ttl time.Duration) error {
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("compressing EPSS data: %w", err)
	}

	now := time.Now()
	_, err = c.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO epss_cache (cve_id, data, fetched_at, expires_at) VALUES (?, ?, ?, ?)",
		cveID, compressed, now.Unix(), now.Add(ttl).Unix(),
	)
	return err
}

func (c *SQLiteCache) GetAdvisory(ctx context.Context, advisoryID string) (*Entry, error) {
	var data []byte
	var source string
	var fetchedAt, expiresAt int64

	err := c.db.QueryRowContext(ctx,
		"SELECT data, source, fetched_at, expires_at FROM advisory_cache WHERE advisory_id = ?",
		advisoryID,
	).Scan(&data, &source, &fetchedAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	decompressed, err := decompress(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing cached advisory data: %w", err)
	}

	return &Entry{
		Data:      decompressed,
		Source:    source,
		FetchedAt: time.Unix(fetchedAt, 0),
		ExpiresAt: time.Unix(expiresAt, 0),
	}, nil
}

func (c *SQLiteCache) SetAdvisory(ctx context.Context, advisoryID string, data []byte, source string, ttl time.Duration) error {
	compressed, err := compress(data)
	if err != nil {
		return fmt.Errorf("compressing advisory data: %w", err)
	}

	now := time.Now()
	_, err = c.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO advisory_cache (advisory_id, data, source, fetched_at, expires_at) VALUES (?, ?, ?, ?, ?)",
		advisoryID, compressed, source, now.Unix(), now.Add(ttl).Unix(),
	)
	return err
}

func (c *SQLiteCache) GetMetadata(ctx context.Context, key string) (string, error) {
	var value string
	err := c.db.QueryRowContext(ctx,
		"SELECT value FROM cache_metadata WHERE key = ?",
		key,
	).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (c *SQLiteCache) SetMetadata(ctx context.Context, key, value string) error {
	_, err := c.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO cache_metadata (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}

func (c *SQLiteCache) Clear(ctx context.Context) error {
	tables := []string{"cve_cache", "kev_cache", "epss_cache", "advisory_cache"}
	for _, table := range tables {
		if _, err := c.db.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	return nil
}

func (c *SQLiteCache) Stats(ctx context.Context) (*Stats, error) {
	s := &Stats{}

	_ = c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM cve_cache").Scan(&s.CVEEntries)
	_ = c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM kev_cache").Scan(&s.KEVEntries)
	_ = c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM epss_cache").Scan(&s.EPSSEntries)
	_ = c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM advisory_cache").Scan(&s.AdvisoryEntries)

	s.TotalEntries = s.CVEEntries + s.KEVEntries + s.EPSSEntries + s.AdvisoryEntries

	// Get database file size
	var dbPath string
	_ = c.db.QueryRowContext(ctx, "PRAGMA database_list").Scan(new(int), new(string), &dbPath)
	if info, err := os.Stat(dbPath); err == nil {
		s.SizeBytes = info.Size()
	}

	return s, nil
}

func (c *SQLiteCache) Close() error {
	return c.db.Close()
}

// compress gzip-compresses data.
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decompress gzip-decompresses data.
func decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

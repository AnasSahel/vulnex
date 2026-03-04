package cache

import (
	"context"
	"time"
)

// Entry represents a cached item with metadata.
type Entry struct {
	Data      []byte
	Source    string
	FetchedAt time.Time
	ExpiresAt time.Time
	ETag      string
}

// Stats holds cache statistics.
type Stats struct {
	TotalEntries    int64
	CVEEntries      int64
	KEVEntries      int64
	EPSSEntries     int64
	AdvisoryEntries int64
	SizeBytes       int64
}

// Cache defines the interface for the local data cache.
type Cache interface {
	// GetCVE retrieves a cached CVE entry by ID.
	GetCVE(ctx context.Context, cveID string) (*Entry, error)

	// SetCVE stores a CVE entry in the cache.
	SetCVE(ctx context.Context, cveID string, data []byte, source string, ttl time.Duration) error

	// GetKEV retrieves the cached KEV catalog.
	GetKEV(ctx context.Context) (*Entry, error)

	// SetKEV stores the KEV catalog in the cache.
	SetKEV(ctx context.Context, data []byte, catalogVersion string, etag string, ttl time.Duration) error

	// GetEPSS retrieves a cached EPSS score by CVE ID.
	GetEPSS(ctx context.Context, cveID string) (*Entry, error)

	// SetEPSS stores an EPSS score in the cache.
	SetEPSS(ctx context.Context, cveID string, data []byte, ttl time.Duration) error

	// GetAdvisory retrieves a cached advisory by ID.
	GetAdvisory(ctx context.Context, advisoryID string) (*Entry, error)

	// SetAdvisory stores an advisory in the cache.
	SetAdvisory(ctx context.Context, advisoryID string, data []byte, source string, ttl time.Duration) error

	// GetMetadata retrieves a metadata value by key.
	GetMetadata(ctx context.Context, key string) (string, error)

	// SetMetadata stores a metadata key-value pair.
	SetMetadata(ctx context.Context, key, value string) error

	// Clear removes all cached data.
	Clear(ctx context.Context) error

	// Stats returns cache statistics.
	Stats(ctx context.Context) (*Stats, error)

	// Close releases cache resources.
	Close() error
}

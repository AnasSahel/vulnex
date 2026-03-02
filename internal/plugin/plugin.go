package plugin

import (
	"context"
	"fmt"
	"sync"

	"github.com/trustin-tech/vulnex/internal/model"
)

// DataSourcePlugin defines the interface that external data source plugins
// must implement to integrate with vulnex.
//
// Plugins provide a way to extend vulnex with additional vulnerability
// intelligence sources beyond the built-in NVD, EPSS, KEV, GHSA, and OSV clients.
type DataSourcePlugin interface {
	// Name returns the unique identifier for this plugin (e.g., "vulncheck", "snyk").
	Name() string

	// Enrich fetches vulnerability data for a specific CVE ID and returns
	// an EnrichedCVE with whatever fields the plugin can populate.
	Enrich(ctx context.Context, cveID string) (*model.EnrichedCVE, error)

	// Search queries the plugin's data source and returns matching vulnerabilities.
	Search(ctx context.Context, query string) ([]*model.EnrichedCVE, error)
}

// Registry manages registered data source plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]DataSourcePlugin
}

// NewRegistry creates a new empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]DataSourcePlugin),
	}
}

// Register adds a plugin to the registry. If a plugin with the same name
// is already registered, it returns an error.
func (r *Registry) Register(plugin DataSourcePlugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := plugin.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %q is already registered", name)
	}

	r.plugins[name] = plugin
	return nil
}

// Get returns the plugin with the given name, or nil if not found.
func (r *Registry) Get(name string) DataSourcePlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.plugins[name]
}

// All returns all registered plugins in no guaranteed order.
func (r *Registry) All() []DataSourcePlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]DataSourcePlugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		result = append(result, p)
	}
	return result
}

// Names returns the names of all registered plugins, sorted alphabetically
// for stable output.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// Count returns the number of registered plugins.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.plugins)
}

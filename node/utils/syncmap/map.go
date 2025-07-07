// Package syncmap provides a map that is safe for concurrent use.
// It is similar to sync.Map, but is simpler, and gives
// a consistent state for range loops.
package syncmap

import (
	"sync"
)

// Map is a map that is safe for concurrent use.
// It is similar to sync.Map, but is simpler, and gives
// a consistent state for range loops.
// It takes two generic types, K (key) and V (value).
// K must be comparable, and V can be any type.
type Map[K comparable, V any] struct {
	mu sync.RWMutex
	m  map[K]V
}

// New creates a new map.
func New[K comparable, V any]() *Map[K, V] {
	return &Map[K, V]{
		m: make(map[K]V),
	}
}

// Get gets a value from the map.
// It returns the value, and whether it was found.
func (m *Map[K, V]) Get(key K) (value V, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.m == nil {
		return value, false
	}
	value, ok = m.m[key]
	return value, ok
}

// Set sets a value in the map.
func (m *Map[K, V]) Set(key K, value V) {
	m.mu.Lock()
	if m.m == nil {
		m.m = make(map[K]V)
	}
	m.m[key] = value
	m.mu.Unlock()
}

// Extract removes and returns the key's value, and whether it was found.
func (m *Map[K, V]) Extract(key K) (value V, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		return
	}
	value, ok = m.m[key]
	delete(m.m, key)
	return
}

// Delete deletes a value from the map.
func (m *Map[K, V]) Delete(key K) bool {
	_, ok := m.Extract(key)
	return ok
}

// Exclusive calls a callback with exclusive access to the map.
// Modifications to the map will be kept.
func (m *Map[K, V]) Exclusive(f func(map[K]V)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.m == nil {
		m.m = make(map[K]V)
	}

	f(m.m)
}

// ExclusiveRead calls a callback with exclusive access to the map.
// It is not safe to modify the map.
func (m *Map[K, V]) ExclusiveRead(f func(map[K]V)) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.m == nil {
		return
	}

	f(m.m)
}

// Clear clears the map.
func (m *Map[K, V]) Clear() {
	m.mu.Lock()
	clear(m.m)
	m.mu.Unlock()
}

package cache

import (
	"sync"
	"time"
)

type Store interface {
	Get(key string) (any, bool)
	Set(key string, value any, ttl time.Duration)
	Delete(key string)
}

type entry struct {
	value     any
	expiresAt time.Time
}

type Cache struct {
	mu    sync.Mutex
	items map[string]entry
}

func New() *Cache {
	return &Cache{items: make(map[string]entry)}
}

func (c *Cache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok || time.Now().After(e.expiresAt) {
		delete(c.items, key)
		return nil, false
	}
	return e.value, true
}

func (c *Cache) Set(key string, value any, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = entry{value: value, expiresAt: time.Now().Add(ttl)}
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}
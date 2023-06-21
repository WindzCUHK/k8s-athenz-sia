package token

import "sync"

type TokenCache interface {
	Update(token Token)
	Load(domain, role string) Token
	Range(func(Token) error) error
}

type LockedTokenCache struct {
	cache map[string]map[string]Token
	lock  sync.RWMutex
}

func (c *LockedTokenCache) Update(t Token) {
	c.lock.Lock()
	defer c.lock.Unlock()
	roleMap := c.cache[t.Domain()]
	if roleMap == nil {
		roleMap = make(map[string]Token)
		c.cache[t.Domain()] = roleMap
	}
	roleMap[t.Role()] = t
}

func (c *LockedTokenCache) Load(domain, role string) Token {
	c.lock.RLock()
	defer c.lock.RUnlock()
	roleMap := c.cache[domain]
	return roleMap[role]
}

func (c *LockedTokenCache) Range(f func(Token) error) error {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, roleMap := range c.cache {
		for _, token := range roleMap {
			err := f(token)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

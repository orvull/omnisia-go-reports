// internal/storage/memory.go
package storage

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/orvull/omnisia-go-reports/internal/models"
)

var (
	// ErrUserExists is returned when attempting to create a user with an existing login.
	ErrUserExists = errors.New("user already exists")
	// ErrUserNotFound is returned when a user cannot be located.
	ErrUserNotFound = errors.New("user not found")
	// ErrRefreshNotFound is returned when a refresh token cannot be located.
	ErrRefreshNotFound = errors.New("refresh token not found")
)

// Store is implemented by memoryStore and should match server.Store needs.
// (Kept here for convenience; server has its own narrowed interface.)
type Store interface {
	// Users
	CreateUser(u *models.User) error
	GetUserByLogin(login string) (*models.User, error)
	GetUserByID(id string) (*models.User, error)
	UpdateUser(u *models.User) error

	// Refresh tokens
	CreateRefresh(rt *models.RefreshToken) error
	GetRefresh(token string) (*models.RefreshToken, error)
	RevokeRefresh(id string) error
	RevokeAllUserRefresh(userID string) error

	// Catalog
	CreateGroup(name, desc string) (id string)
	CreatePermission(name, desc string) (id string)
	CreateScope(name, desc string) (id string)
}

// memoryStore is a thread-safe in-memory implementation suitable for tests and local dev.
// Swap this out for Postgres/Redis in production.
type memoryStore struct {
	mu sync.RWMutex

	usersByLogin map[string]*models.User
	usersByID    map[string]*models.User

	refreshByToken map[string]*models.RefreshToken // key: opaque token

	groups map[string]*models.Group
	perms  map[string]*models.Permission
	scopes map[string]*models.Scope
}

// NewMemory creates an empty in-memory store.
func NewMemory() *memoryStore {
	return &memoryStore{
		usersByLogin:   make(map[string]*models.User),
		usersByID:      make(map[string]*models.User),
		refreshByToken: make(map[string]*models.RefreshToken),
		groups:         make(map[string]*models.Group),
		perms:          make(map[string]*models.Permission),
		scopes:         make(map[string]*models.Scope),
	}
}

// ---------- Users ----------

func (m *memoryStore) CreateUser(u *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.usersByLogin[u.Login]; exists {
		return ErrUserExists
	}
	u.ID = uuid.NewString()
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now

	// store pointers; callers get copies via getters
	cp := *u
	m.usersByLogin[u.Login] = &cp
	m.usersByID[u.ID] = &cp
	return nil
}

func (m *memoryStore) GetUserByLogin(login string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.usersByLogin[login]
	if !ok {
		return nil, ErrUserNotFound
	}
	cp := *u
	// deep copy slices to avoid external mutation
	if u.Groups != nil {
		cp.Groups = append([]string(nil), u.Groups...)
	}
	return &cp, nil
}

func (m *memoryStore) GetUserByID(id string) (*models.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.usersByID[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	cp := *u
	if u.Groups != nil {
		cp.Groups = append([]string(nil), u.Groups...)
	}
	return &cp, nil
}

func (m *memoryStore) UpdateUser(u *models.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// locate by login (authoritative key) or by ID
	current, ok := m.usersByLogin[u.Login]
	if !ok {
		// if login changed, try id
		if u.ID != "" {
			current, ok = m.usersByID[u.ID]
		}
		if !ok {
			return ErrUserNotFound
		}
	}

	// update fields
	current.PasswordHash = u.PasswordHash
	current.UserVer = u.UserVer
	current.Groups = append([]string(nil), u.Groups...)
	current.UpdatedAt = time.Now()

	// maintain ID and maps
	if current.ID == "" && u.ID != "" {
		current.ID = u.ID
	}
	m.usersByLogin[current.Login] = current
	if current.ID != "" {
		m.usersByID[current.ID] = current
	}
	return nil
}

// ---------- Refresh Tokens ----------

func (m *memoryStore) CreateRefresh(rt *models.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rt.ID == "" {
		rt.ID = uuid.NewString()
	}
	// store a copy
	cp := *rt
	m.refreshByToken[rt.Token] = &cp
	return nil
}

func (m *memoryStore) GetRefresh(token string) (*models.RefreshToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rt, ok := m.refreshByToken[token]
	if !ok {
		return nil, ErrRefreshNotFound
	}
	cp := *rt
	return &cp, nil
}

func (m *memoryStore) RevokeRefresh(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for tok, v := range m.refreshByToken {
		if v.ID == id {
			// mark revoked in-place
			v.Revoked = true
			m.refreshByToken[tok] = v
		}
	}
	return nil
}

func (m *memoryStore) RevokeAllUserRefresh(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for tok, v := range m.refreshByToken {
		if v.UserID == userID {
			v.Revoked = true
			m.refreshByToken[tok] = v
		}
	}
	return nil
}

// ---------- Catalog (Group/Permission/Scope) ----------

func (m *memoryStore) CreateGroup(name, desc string) (id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = uuid.NewString()
	m.groups[id] = &models.Group{
		ID:          id,
		Name:        name,
		Description: desc,
		CreatedAt:   time.Now(),
	}
	return id
}

func (m *memoryStore) CreatePermission(name, desc string) (id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = uuid.NewString()
	m.perms[id] = &models.Permission{
		ID:          id,
		Name:        name,
		Description: desc,
		CreatedAt:   time.Now(),
	}
	return id
}

func (m *memoryStore) CreateScope(name, desc string) (id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	id = uuid.NewString()
	m.scopes[id] = &models.Scope{
		ID:          id,
		Name:        name,
		Description: desc,
		CreatedAt:   time.Now(),
	}
	return id
}

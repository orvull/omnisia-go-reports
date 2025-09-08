package models

import (
	"time"
)

type User struct {
	ID           string
	Login        string
	PasswordHash string
	UserVer      int64
	Groups       []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type RefreshToken struct {
	ID        string
	UserID    string
	Token     string // opaque
	ExpiresAt time.Time
	Revoked   bool
	IssuedAt  time.Time
}

type Group struct {
	ID, Name, Description string
	CreatedAt             time.Time
}

type Permission struct {
	ID, Name, Description string
	CreatedAt             time.Time
}

type Scope struct {
	ID, Name, Description string
	CreatedAt             time.Time
}

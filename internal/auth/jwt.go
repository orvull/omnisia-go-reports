package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID  string   `json:"uid"`
	Login   string   `json:"login"`
	UserVer int64    `json:"user_ver"`
	Groups  []string `json:"groups"`
	jwt.RegisteredClaims
}

type JWTSigner struct {
	Key []byte
	TTL time.Duration
}

func (s JWTSigner) Issue(userID, login string, userVer int64, groups []string) (string, error) {
	claims := Claims{
		UserID:  userID,
		Login:   login,
		UserVer: userVer,
		Groups:  groups,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.TTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "",
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(s.Key)
}

func (s JWTSigner) Parse(token string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(token, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.Key, nil
	})
	if err != nil {
		return nil, err
	}
	if c, ok := t.Claims.(*Claims); ok && t.Valid {
		return c, nil
	}
	return nil, errors.New("invalid token")
}

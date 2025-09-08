// internal/server/server.go
package server

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/orvull/omnisia-go-reports/gen/admin_auth"
	"github.com/orvull/omnisia-go-reports/internal/auth"
	"github.com/orvull/omnisia-go-reports/internal/google"
	"github.com/orvull/omnisia-go-reports/internal/models"
	"github.com/orvull/omnisia-go-reports/internal/storage"
)

// Service implements admin_auth.AdminAuthServiceServer.
type Service struct {
	admin_auth.UnimplementedAdminAuthServiceServer

	store      Store // superset of storage.Store with GetUserByID
	jwt        auth.JWTSigner
	refreshTTL time.Duration
	googleV    google.Verifier
}

// Store describes the persistence the service needs.
// Your memory or Postgres implementation should satisfy this.
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

// New constructs the gRPC service.
func New(store Store, signer auth.JWTSigner, refreshTTL time.Duration, gv google.Verifier) *Service {
	return &Service{
		store:      store,
		jwt:        signer,
		refreshTTL: refreshTTL,
		googleV:    gv,
	}
}

// ---------- RPCs ----------

func (s *Service) Ping(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

func (s *Service) Register(ctx context.Context, req *admin_auth.AdminAuthRegisterUserGrpcRequest) (*admin_auth.AdminAuthRegisterUserGrpcResponse, error) {
	login := req.GetLogin()
	pw := req.GetPassword()
	if login == "" || pw == "" {
		return &admin_auth.AdminAuthRegisterUserGrpcResponse{Error: ptrErr(admin_auth.AuthError_InvalidLogin)}, nil
	}

	hash, err := auth.HashPassword(pw)
	if err != nil {
		return nil, err
	}

	u := &models.User{
		Login:        login,
		PasswordHash: hash,
		UserVer:      1,
	}
	if err := s.store.CreateUser(u); err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			return &admin_auth.AdminAuthRegisterUserGrpcResponse{Error: ptrErr(admin_auth.AuthError_LoginAlreadyInUse)}, nil
		}
		return nil, err
	}

	at, rt, err := s.issueTokens(u)
	if err != nil {
		return nil, err
	}
	return &admin_auth.AdminAuthRegisterUserGrpcResponse{AuthToken: &at, RefreshToken: &rt}, nil
}

func (s *Service) Authenticate(ctx context.Context, req *admin_auth.AdminAuthenticateGrpcRequest) (*admin_auth.AdminAuthenticateGrpcResponse, error) {
	u, err := s.store.GetUserByLogin(req.GetLogin())
	if err != nil {
		return &admin_auth.AdminAuthenticateGrpcResponse{Error: ptrErr(admin_auth.AuthError_UserNotFound)}, nil
	}
	if !auth.CheckPassword(u.PasswordHash, req.GetPassword()) {
		return &admin_auth.AdminAuthenticateGrpcResponse{Error: ptrErr(admin_auth.AuthError_InvalidPassword)}, nil
	}

	at, rt, err := s.issueTokens(u)
	if err != nil {
		return nil, err
	}
	return &admin_auth.AdminAuthenticateGrpcResponse{AuthToken: &at, RefreshToken: &rt}, nil
}

func (s *Service) UpdatePassword(ctx context.Context, req *admin_auth.AdminAuthUpdatePasswordGrpcRequest) (*admin_auth.AdminAuthUpdatePasswordGrpcResponse, error) {
	u, err := s.store.GetUserByLogin(req.GetLogin())
	if err != nil {
		return &admin_auth.AdminAuthUpdatePasswordGrpcResponse{Error: ptrErr(admin_auth.AuthError_UserNotFound)}, nil
	}

	hash, err := auth.HashPassword(req.GetNewPassword())
	if err != nil {
		return nil, err
	}

	u.PasswordHash = hash
	u.UserVer++ // invalidate all existing ATs via version check
	if err := s.store.UpdateUser(u); err != nil {
		return nil, err
	}

	// Optional security hardening: revoke all refresh tokens on password change
	_ = s.store.RevokeAllUserRefresh(u.ID)

	at, rt, err := s.issueTokens(u)
	if err != nil {
		return nil, err
	}
	return &admin_auth.AdminAuthUpdatePasswordGrpcResponse{AuthToken: &at, RefreshToken: &rt}, nil
}

func (s *Service) Refresh(ctx context.Context, req *admin_auth.AdminAuthRefreshGrpcRequest) (*admin_auth.AdminAuthRefreshGrpcResponse, error) {
	rt, err := s.store.GetRefresh(req.GetRefreshToken())
	if err != nil || rt.Revoked || time.Now().After(rt.ExpiresAt) {
		return &admin_auth.AdminAuthRefreshGrpcResponse{Error: ptrErr(admin_auth.AuthError_InvalidToken)}, nil
	}

	u, err := s.store.GetUserByID(rt.UserID)
	if err != nil {
		return &admin_auth.AdminAuthRefreshGrpcResponse{Error: ptrErr(admin_auth.AuthError_UserNotFound)}, nil
	}

	// Rotate RT (best practice)
	_ = s.store.RevokeRefresh(rt.ID)

	at, newRT, err := s.issueTokens(u)
	if err != nil {
		return nil, err
	}
	return &admin_auth.AdminAuthRefreshGrpcResponse{AuthToken: &at, RefreshToken: &newRT}, nil
}

func (s *Service) Validate(ctx context.Context, req *admin_auth.AdminAuthValidateJwtRequest) (*admin_auth.AdminAuthValidateJwtResponse, error) {
	claims, err := s.jwt.Parse(req.GetAuthToken())
	if err != nil {
		return &admin_auth.AdminAuthValidateJwtResponse{Error: ptrErr(admin_auth.AuthError_InvalidToken)}, nil
	}

	u, err := s.store.GetUserByLogin(claims.Login)
	if err != nil {
		return &admin_auth.AdminAuthValidateJwtResponse{Error: ptrErr(admin_auth.AuthError_UserNotFound)}, nil
	}
	if u.UserVer != claims.UserVer {
		return &admin_auth.AdminAuthValidateJwtResponse{Error: ptrErr(admin_auth.AuthError_StaleToken)}, nil
	}
	return &admin_auth.AdminAuthValidateJwtResponse{}, nil
}

func (s *Service) AuthenticateGoogle(ctx context.Context, req *admin_auth.AdminAuthGoogleGrpcRequest) (*admin_auth.AdminAuthGoogleGrpcResponse, error) {
	prof, err := s.googleV.VerifyIDToken(ctx, req.GetIdToken())
	if err != nil {
		return &admin_auth.AdminAuthGoogleGrpcResponse{Error: ptrErr(admin_auth.AuthError_InvalidToken)}, nil
	}

	u, err := s.store.GetUserByLogin(prof.Email)
	if err != nil {
		// Auto-provision user on first Google login
		randomPW := uuid.NewString()
		hash, _ := auth.HashPassword(randomPW)
		u = &models.User{Login: prof.Email, PasswordHash: hash, UserVer: 1}
		_ = s.store.CreateUser(u)
	}

	at, rt, err := s.issueTokens(u)
	if err != nil {
		return nil, err
	}
	return &admin_auth.AdminAuthGoogleGrpcResponse{AuthToken: &at, RefreshToken: &rt}, nil
}

func (s *Service) CreateGroup(ctx context.Context, req *admin_auth.AdminAuthCreateGroupGrpcRequest) (*admin_auth.AdminAuthCreateGroupGrpcResponse, error) {
	id := s.store.CreateGroup(req.GetName(), req.GetDescription())
	return &admin_auth.AdminAuthCreateGroupGrpcResponse{GroupId: &id}, nil
}

func (s *Service) CreatePermission(ctx context.Context, req *admin_auth.AdminAuthCreatePermissionGrpcRequest) (*admin_auth.AdminAuthCreatePermissionGrpcResponse, error) {
	id := s.store.CreatePermission(req.GetName(), req.GetDescription())
	return &admin_auth.AdminAuthCreatePermissionGrpcResponse{PermissionId: &id}, nil
}

func (s *Service) CreateScope(ctx context.Context, req *admin_auth.AdminAuthCreateScopeGrpcRequest) (*admin_auth.AdminAuthCreateScopeGrpcResponse, error) {
	id := s.store.CreateScope(req.GetName(), req.GetDescription())
	return &admin_auth.AdminAuthCreateScopeGrpcResponse{ScopeId: &id}, nil
}

// ---------- helpers ----------

func (s *Service) issueTokens(u *models.User) (accessToken string, refreshToken string, err error) {
	at, err := s.jwt.Issue(u.ID, u.Login, u.UserVer, u.Groups)
	if err != nil {
		return "", "", err
	}

	rt := &models.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    u.ID,
		Token:     uuid.NewString(), // opaque
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(s.refreshTTL),
		Revoked:   false,
	}
	if err := s.store.CreateRefresh(rt); err != nil {
		return "", "", err
	}
	return at, rt.Token, nil
}

func ptrErr(e admin_auth.AuthError) *admin_auth.AuthError { return &e }

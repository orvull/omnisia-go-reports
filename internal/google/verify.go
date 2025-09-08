package google

import (
	"context"
	"errors"

	"google.golang.org/api/idtoken"
)

type Verifier struct{ ClientID string }

type GoogleProfile struct{ Email string }

func (v Verifier) VerifyIDToken(ctx context.Context, idTok string) (*GoogleProfile, error) {
	if v.ClientID == "" {
		return nil, errors.New("google client id not configured")
	}
	payload, err := idtoken.Validate(ctx, idTok, v.ClientID)
	if err != nil {
		return nil, err
	}
	email, _ := payload.Claims["email"].(string)
	if email == "" {
		return nil, errors.New("email not present in id token")
	}
	return &GoogleProfile{Email: email}, nil
}

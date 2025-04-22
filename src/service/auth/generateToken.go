package auth

import (
	"awesomeProject1/errHandler"
	"context"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func (s *Service) GenerateToken(GUID, ip string, ctx context.Context) (string, string, *errHandler.CustomError) {
	expiresAt := jwt.NewNumericDate(time.Now().Add(24 * time.Hour))

	var rTokenID int
	refreshToken, rTokenID, customErr := s.GenerateRefreshToken(GUID, ip, ctx)
	if customErr != nil {
		return "", "", customErr
	}

	claims := &Claims{
		GUID:           GUID,
		Ip:             ip,
		RefreshTokenID: rTokenID,

		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: expiresAt,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString([]byte(s.tokenKey))
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInternal, err)
	}

	return tokenString, refreshToken, nil
}

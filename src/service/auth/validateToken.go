package auth

import (
	"awesomeProject1/errHandler"
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

func (s *Service) ValidateToken(tokenString string, ctx context.Context) (*Claims, *errHandler.CustomError) {
	if tokenString == "" {
		return nil, errHandler.New(errHandler.ErrInvalidToken, nil)
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.tokenKey), nil
	})
	if err != nil {
		return nil, errHandler.New(errHandler.ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errHandler.New(errHandler.ErrInvalidToken, errors.New("не удалось распарсить токен"))
	}

	if str, err := s.db.GetRefreshTokenID(claims.RefreshTokenID, ctx); err != nil || str == "" {
		return nil, errHandler.New(errHandler.ErrInvalidToken, err)
	}

	return claims, nil
}

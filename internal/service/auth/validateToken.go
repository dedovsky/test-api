package auth

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("token не может быть пустым")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.tokenKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("неверный токен")
	}

	if str, err := s.db.GetRefreshTokenID(claims.RefreshTokenID); err != nil || str == "" {
		return nil, errors.New("неверный токен")
	}

	return claims, nil
}

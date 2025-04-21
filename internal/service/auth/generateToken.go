package auth

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func (s *Service) GenerateToken(GUID, ip string) (tokenString, refreshToken string, err error) {
	expiresAt := jwt.NewNumericDate(time.Now().Add(24 * time.Hour))

	var rTokenID int
	refreshToken, rTokenID, err = s.GenerateRefreshToken(GUID, ip)
	if err != nil {
		return "", "", errors.New("ошибка генерации токена")
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

	tokenString, err = token.SignedString([]byte(s.tokenKey))
	if err != nil {
		err = errors.New("internal error")
		return
	}

	return
}

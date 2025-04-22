package auth

import (
	"awesomeProject1/errHandler"
	"awesomeProject1/service"
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type RefreshTokenPayload struct {
	GUID           string `json:"guid"`
	Ip             string `json:"ip"`
	RefreshTokenID int    `json:"refresh_token_id"`
	Token          string `json:"token"`

	jwt.RegisteredClaims
}

func (s *Service) GenerateRefreshToken(GUID, ip string, ctx context.Context) (string, int, *errHandler.CustomError) {
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	tokenStr := base64.RawURLEncoding.EncodeToString(tokenBytes)

	encryptedToken, err := bcrypt.GenerateFromPassword([]byte(tokenStr), bcrypt.DefaultCost)
	if err != nil {
		return "", 0, errHandler.New(errHandler.ErrInternal, err)
	}

	rTokenID, err := s.db.NewRefreshToken(encryptedToken, ctx)
	if err != nil {
		return "", 0, errHandler.New(errHandler.ErrInternal, err)
	}

	claims := &RefreshTokenPayload{
		GUID:           GUID,
		Ip:             ip,
		Token:          tokenStr,
		RefreshTokenID: rTokenID,

		RegisteredClaims: jwt.RegisteredClaims{},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, *claims)
	rToken, err := token.SignedString([]byte(s.refreshKey))
	if err != nil {
		return "", 0, errHandler.New(errHandler.ErrInternal, err)
	}

	return rToken, rTokenID, nil
}

func (s *Service) RenewTokens(rTokenBase64, ip string, ctx context.Context) (string, string, *errHandler.CustomError) {
	token, err := jwt.ParseWithClaims(rTokenBase64, &RefreshTokenPayload{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.refreshKey), nil
	})
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*RefreshTokenPayload)
	if !ok || !token.Valid {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	bcryptHash, err := s.db.GetRefreshTokenID(claims.RefreshTokenID, ctx)
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(bcryptHash), []byte(claims.Token))
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	if claims.Ip != ip {
		// Ошибка залогирована через обработчик, а возвращать клиенту и прерывать исполнение функции нет смысла
		_ = service.SendEmail(claims.GUID, claims.Ip, ip)
	}

	newToken, newRefreshToken, customErr := s.GenerateToken(claims.GUID, ip, ctx)
	if customErr != nil {
		return "", "", errHandler.New(errHandler.ErrInternal, err)
	}

	err = s.db.DeleteRefreshToken(claims.RefreshTokenID, ctx)
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInternal, err)
	}

	return newToken, newRefreshToken, nil

}

package auth

import (
	"awesomeProject1/errHandler"
	"awesomeProject1/service"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
)

type RefreshTokenPayload struct {
	GUID           string `json:"guid"`
	Ip             string `json:"ip"`
	RefreshTokenID int    `json:"refresh_token_id"`
	Token          string `json:"token"`
}

func (s *Service) GenerateRefreshToken(GUID, ip string, ctx context.Context) (string, int, error) {
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)

	tokenStr := base64.RawURLEncoding.EncodeToString(tokenBytes)

	encryptedToken, err := bcrypt.GenerateFromPassword(tokenBytes, bcrypt.DefaultCost)
	if err != nil {
		return "", 0, errHandler.New(errHandler.ErrInternal, err)
	}

	rTokenID, err := s.db.NewRefreshToken(encryptedToken, ctx)
	if err != nil {
		return "", 0, errHandler.New(errHandler.ErrInternal, err)
	}

	payload := RefreshTokenPayload{
		GUID:           GUID,
		Ip:             ip,
		RefreshTokenID: rTokenID,
		Token:          tokenStr,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", 0, errHandler.New(errHandler.ErrInternal, err)
	}

	mac := hmac.New(sha256.New, []byte(s.refreshKey))
	mac.Write(payloadBytes)
	signature := mac.Sum(nil)

	rToken := append(payloadBytes, signature...)

	rTokenBase64 := base64.StdEncoding.EncodeToString(rToken)

	return rTokenBase64, rTokenID, nil

}

func (s *Service) RenewTokens(rTokenBase64, ip string, ctx context.Context) (string, string, *errHandler.CustomError) {
	data, err := base64.StdEncoding.DecodeString(rTokenBase64)
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	if len(data) < 32 {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	payloadBytes, signature := data[:len(data)-32], data[len(data)-32:]

	mac := hmac.New(sha256.New, []byte(s.refreshKey))
	mac.Write(payloadBytes)
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	var payload RefreshTokenPayload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	tokenBytes, err := base64.RawURLEncoding.DecodeString(payload.Token)
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	bcryptHash, err := s.db.GetRefreshTokenID(payload.RefreshTokenID, ctx)
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(bcryptHash), tokenBytes)
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInvalidToken, err)
	}

	if payload.Ip != ip {
		// Ошибка залогирована через обработчик, а возвращать клиенту и прерывать исполнение функции нет смысла
		_ = service.SendEmail(payload.GUID, payload.Ip, ip)
	}

	newToken, newRefreshToken, customErr := s.GenerateToken(payload.GUID, ip, ctx)
	if customErr != nil {
		return "", "", errHandler.New(errHandler.ErrInternal, customErr)
	}

	err = s.db.DeleteRefreshToken(payload.RefreshTokenID, ctx)
	if err != nil {
		return "", "", errHandler.New(errHandler.ErrInternal, err)
	}

	return newToken, newRefreshToken, nil
}

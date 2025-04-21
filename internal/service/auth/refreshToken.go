package auth

import (
	"awesomeProject1/internal/service"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/bcrypt"
)

type RefreshTokenPayload struct {
	GUID           string `json:"guid"`
	Ip             string `json:"ip"`
	RefreshTokenID int    `json:"refresh_token_id"`
	Token          string `json:"token"`
}

func (s *Service) GenerateRefreshToken(GUID, ip string) (string, int, error) {
	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)

	tokenStr := base64.RawURLEncoding.EncodeToString(tokenBytes)

	encryptedToken, err := bcrypt.GenerateFromPassword(tokenBytes, bcrypt.DefaultCost)
	if err != nil {
		return "", 0, errors.New("internal error")
	}

	rTokenID, err := s.db.NewRefreshToken(encryptedToken)
	if err != nil {
		return "", 0, errors.New("internal error")
	}

	payload := RefreshTokenPayload{
		GUID:           GUID,
		Ip:             ip,
		RefreshTokenID: rTokenID,
		Token:          tokenStr,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", 0, errors.New("internal error")
	}

	mac := hmac.New(sha256.New, []byte(s.refreshKey))
	mac.Write(payloadBytes)
	signature := mac.Sum(nil)

	rToken := append(payloadBytes, signature...)

	rTokenBase64 := base64.StdEncoding.EncodeToString(rToken)

	return rTokenBase64, rTokenID, nil

}

func (s *Service) RenewTokens(rTokenBase64 string, ip string) (string, string, error) {
	data, err := base64.StdEncoding.DecodeString(rTokenBase64)
	if err != nil {
		return "", "", errors.New("токен должен быть в base64")
	}

	if len(data) < 32 {
		return "", "", errors.New("неверный формат токена")
	}

	payloadBytes, signature := data[:len(data)-32], data[len(data)-32:]

	mac := hmac.New(sha256.New, []byte(s.refreshKey))
	mac.Write(payloadBytes)
	expectedSignature := mac.Sum(nil)
	if !hmac.Equal(signature, expectedSignature) {
		return "", "", errors.New("токен изменен")
	}

	var payload RefreshTokenPayload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return "", "", errors.New("неверный формат токена")
	}

	tokenBytes, err := base64.RawURLEncoding.DecodeString(payload.Token)
	if err != nil {
		return "", "", errors.New("неверный формат токена")
	}

	bcryptHash, err := s.db.GetRefreshTokenID(payload.RefreshTokenID)
	if err != nil {
		return "", "", errors.New("токен не найден")
	}

	err = bcrypt.CompareHashAndPassword([]byte(bcryptHash), tokenBytes)
	if err != nil {
		return "", "", errors.New("неверный refresh token")
	}

	if payload.Ip != ip {
		err = service.SendEmail(payload.GUID, payload.Ip, ip)
		if err != nil {
			return "", "", err
		}
	}

	newToken, newRefreshToken, err := s.GenerateToken(payload.GUID, ip)
	if err != nil {
		return "", "", err
	}

	err = s.db.DeleteRefreshToken(payload.RefreshTokenID)
	if err != nil {
		return "", "", err
	}

	return newToken, newRefreshToken, nil

}

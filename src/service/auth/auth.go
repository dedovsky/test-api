package auth

import (
	"awesomeProject1/repository/postgres"
	"github.com/golang-jwt/jwt/v5"
)

type Service struct {
	tokenKey   string
	refreshKey string
	db         *postgres.Repository
}

type Claims struct {
	GUID           string `json:"guid"`
	Ip             string `json:"ip"`
	RefreshTokenID int    `json:"refresh_token_id"`

	jwt.RegisteredClaims
}

func NewService(tokenKey, rTokenKey string, db *postgres.Repository) *Service {
	return &Service{
		tokenKey:   tokenKey,
		refreshKey: rTokenKey,
		db:         db,
	}
}

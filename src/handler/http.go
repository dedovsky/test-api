package handler

import (
	"awesomeProject1/service/auth"
	"github.com/gin-gonic/gin"
	"log"
)

type AuthHandler struct {
	*auth.Service
}

func ListenAndServe(Service *auth.Service) {
	router := gin.Default()

	authGroup := router.Group("/auth")

	authHandler := &AuthHandler{
		Service,
	}

	authGroup.GET("/token", authHandler.getToken)
	authGroup.POST("/refresh", authHandler.refreshToken)
	// В ТЗ не сказано, но для удобства добавил валидацию токена
	authGroup.GET("/validate", authHandler.validateToken)

	log.Fatal(router.Run(":8080"))
}

func (auth *AuthHandler) getToken(c *gin.Context) {
	GUID := c.Query("guid")
	if GUID == "" {
		c.JSON(400, gin.H{"error": "guid не может быть пустым"})
		return
	}

	token, refreshToken, err := auth.GenerateToken(GUID, c.ClientIP(), c)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"token": token, "refresh_token": refreshToken})
}

type ValidateTokenRequest struct {
	Token string `json:"token"`
}

func (auth *AuthHandler) validateToken(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(400, gin.H{"error": "токен не может быть пустым"})
	}

	_, err := auth.ValidateToken(token, c)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "токен валиден"})
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (auth *AuthHandler) refreshToken(c *gin.Context) {
	rToken := &RefreshTokenRequest{}
	err := c.ShouldBindBodyWithJSON(rToken)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if rToken.RefreshToken == "" {
		c.JSON(400, gin.H{"error": "refresh_token не может быть пустым"})
		return
	}

	token, refreshToken, customErr := auth.RenewTokens(rToken.RefreshToken, c.ClientIP(), c)
	if customErr != nil {
		c.JSON(customErr.Code, gin.H{"error": customErr.Message})
		return
	}

	c.JSON(200, gin.H{"token": token, "refresh_token": refreshToken})

}

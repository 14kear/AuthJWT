package middleware

import (
	"github.com/14kear/TestingQuestionJWT/auth/internal/lib/jwt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func AuthMiddleware(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// CORS-заголовки для токенов
		c.Header("Access-Control-Expose-Headers", "X-New-Access-Token, X-New-Refresh-Token")

		accessToken := extractTokenFromHeader(c.GetHeader("Authorization"))

		if accessToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing access token"})
			return
		}

		claims, err := jwt.ParseToken(accessToken, secret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("user_guid", claims.GUID)
		c.Set("session_id", claims.SessionID)

		// Пропускаем запрос дальше с новыми токенами
		c.Next()
	}
}

func extractTokenFromHeader(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	return parts[1]
}

package handlers

import (
	"github.com/14kear/TestingQuestionJWT/auth/internal/services"
	"github.com/gin-gonic/gin"
	"net/http"
)

type AuthHandler struct {
	auth       *services.Auth
	webhookURL string
}

func NewAuthHandler(auth *services.Auth, webhookURL string) *AuthHandler {
	return &AuthHandler{auth: auth, webhookURL: webhookURL}
}

func (h *AuthHandler) Register(ctx *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	guid, err := h.auth.RegisterNewUser(ctx, req.Email, req.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"guid": guid})
}

func (h *AuthHandler) Login(ctx *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tokenPair, guid, err := h.auth.Login(ctx, req.Email, req.Password)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"guid": guid, "access_token": tokenPair.AccessToken, "refresh_token": tokenPair.RefreshToken})
}

func (h *AuthHandler) Logout(ctx *gin.Context) {
	err := h.auth.Logout(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func (h *AuthHandler) GetCurrentUserGUID(ctx *gin.Context) {
	guid, err := h.auth.GetCurrentUserGUID(ctx)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"guid": guid})
}

func (h *AuthHandler) GetTokenPairByUserGUID(ctx *gin.Context) {
	var req struct {
		GUID string `json:"guid" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tokenPair, err := h.auth.GetTokenPairByUserGUID(ctx, req.GUID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"access_token": tokenPair.AccessToken, "refresh_token": tokenPair.RefreshToken})
}

func (h *AuthHandler) RefreshTokens(ctx *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	tokenPair, err := h.auth.RefreshTokens(ctx, req.RefreshToken, h.webhookURL)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"access_token": tokenPair.AccessToken, "refresh_token": tokenPair.RefreshToken})
}

package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/14kear/TestingQuestionJWT/auth/internal/entity"
	"github.com/14kear/TestingQuestionJWT/auth/internal/lib/jwt"
	"github.com/14kear/TestingQuestionJWT/auth/internal/repo"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrAccessDenied       = errors.New("access denied")
)

type TokenRepository interface {
	SaveToken(ctx *gin.Context, token *entity.RefreshToken) error
	GetRefreshTokenByUserGUID(ctx *gin.Context, guid string) (*entity.RefreshToken, error)
	DeleteTokenByUserGUID(ctx *gin.Context, guid string) error
}

type UserRepository interface {
	SaveUser(ctx *gin.Context, email string, passHash []byte) (guid string, err error)
	GetUserByEmail(ctx *gin.Context, email string) (user entity.User, err error)
	GetUserByGUID(ctx *gin.Context, guid string) (entity.User, error)
}

type Auth struct {
	log             *slog.Logger
	tokenRepo       TokenRepository
	userRepo        UserRepository
	jwtSecret       string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

func NewAuth(log *slog.Logger,
	tokenRepo TokenRepository,
	userRepo UserRepository,
	jwtSecret string,
	accessTokenTTL,
	refreshTokenTTL time.Duration) *Auth {
	return &Auth{
		log:             log,
		tokenRepo:       tokenRepo,
		userRepo:        userRepo,
		jwtSecret:       jwtSecret,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

func (auth *Auth) RegisterNewUser(ctx *gin.Context, email string, password string) (string, error) {
	const op = "auth.RegisterNewUser"

	log := auth.log.With(slog.String("operation", op))
	log.Info("registering new user")

	// хэш пароля + соль
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate hash password", err)

		return "", fmt.Errorf("%s: %w", op, err)
	}

	guid, err := auth.userRepo.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, repo.ErrUserAlreadyExists) {
			log.Warn("user already exists", err)
			return "", ErrUserExists
		}
		log.Error("failed to save user", err)

		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("successfully registered new user")
	return guid, nil
}

func (auth *Auth) Login(ctx *gin.Context, email string, password string) (jwt.TokenPair, string, error) {
	const op = "auth.Login"

	log := auth.log.With(slog.String("op", op), slog.String("email", email))
	log.Info("attempting to login user")

	user, err := auth.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repo.ErrUserNotFound) {
			log.Info("user not found")
			return jwt.TokenPair{}, "", ErrUserNotFound
		}

		log.Error("failed to find user", err)
		return jwt.TokenPair{}, "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", err)
		return jwt.TokenPair{}, "", ErrInvalidCredentials
	}

	log.Info("successfully logged in")

	sessionID := uuid.New().String()

	tokenPair, err := jwt.NewTokenPair(user, auth.accessTokenTTL, auth.jwtSecret, sessionID)
	if err != nil {
		log.Error("failed to generate token pair", err)
		return jwt.TokenPair{}, "", fmt.Errorf("%s: %w", op, err)
	}

	userAgent := ctx.GetHeader("User-Agent")
	ip := ctx.ClientIP()

	refreshToken := entity.RefreshToken{
		UserGUID:  user.GUID,
		TokenHash: tokenPair.RefreshTokenHash,
		UserAgent: userAgent,
		IP:        ip,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(auth.refreshTokenTTL),
		CreatedAt: time.Now(),
	}

	errTokenSave := auth.tokenRepo.SaveToken(ctx, &refreshToken)
	if errTokenSave != nil {
		log.Error("failed to save refresh token", errTokenSave)
		return jwt.TokenPair{}, "", fmt.Errorf("%s: failed to store refresh token: %w", op, errTokenSave)
	}

	return jwt.TokenPair{AccessToken: tokenPair.AccessToken, RefreshToken: tokenPair.RefreshToken, RefreshTokenHash: tokenPair.RefreshTokenHash}, user.GUID, nil
}

func (auth *Auth) GetTokenPairByUserGUID(ctx *gin.Context, guid string) (jwt.TokenPair, error) {
	const op = "auth.GetTokenPairByUserGUID"

	log := auth.log.With(slog.String("op", op), slog.String("guid", guid))
	log.Info("getting token pair by user guid")

	currentUserGUID, err := auth.GetCurrentUserGUID(ctx)
	if err != nil {
		log.Error("failed to get current user GUID", err)
		return jwt.TokenPair{}, fmt.Errorf("%s: %w", op, err)
	}

	if currentUserGUID != guid {
		log.Error("invalid user GUID")
		return jwt.TokenPair{}, ErrAccessDenied
	}

	user, err := auth.userRepo.GetUserByGUID(ctx, guid)
	if err != nil {
		if errors.Is(err, repo.ErrUserNotFound) {
			return jwt.TokenPair{}, ErrUserNotFound
		}
		log.Error("failed to get token pair", err)
		return jwt.TokenPair{}, err
	}

	sessionID := uuid.New().String()

	newTokenPair, err := jwt.NewTokenPair(user, auth.accessTokenTTL, auth.jwtSecret, sessionID)
	if err != nil {
		log.Error("failed to generate token pair", err)
		return jwt.TokenPair{}, fmt.Errorf("%s: %w", op, err)
	}

	userAgent := ctx.GetHeader("User-Agent")
	ip := ctx.ClientIP()

	refreshToken := entity.RefreshToken{
		UserGUID:  user.GUID,
		TokenHash: newTokenPair.RefreshTokenHash,
		UserAgent: userAgent,
		IP:        ip,
		SessionID: sessionID,
		ExpiresAt: time.Now().Add(auth.refreshTokenTTL),
		CreatedAt: time.Now(),
	}

	errTokenSave := auth.tokenRepo.SaveToken(ctx, &refreshToken)
	if errTokenSave != nil {
		log.Error("failed to save refresh token", errTokenSave)
		return jwt.TokenPair{}, fmt.Errorf("%s: failed to store refresh token: %w", op, errTokenSave)
	}

	log.Info("successfully retrieved token pair")

	return jwt.TokenPair{AccessToken: newTokenPair.AccessToken, RefreshToken: newTokenPair.RefreshToken, RefreshTokenHash: newTokenPair.RefreshTokenHash}, nil
}

func (auth *Auth) GetCurrentUserGUID(ctx *gin.Context) (string, error) {
	const op = "auth.GetCurrentUserGuid"

	log := auth.log.With(slog.String("op", op))
	log.Info("getting current user guid")

	guid, exists := ctx.Get("user_guid")
	if !exists {
		return "", ErrUserNotFound
	}

	userGUID, ok := guid.(string)
	if !ok {
		return "", ErrInvalidToken
	}

	log.Info("got current user guid")

	return userGUID, nil
}

func (auth *Auth) RefreshTokens(ctx *gin.Context, refreshToken string, webhookURL string) (jwt.TokenPair, error) {
	const op = "auth.RefreshTokens"

	log := auth.log.With(slog.String("op", op))
	log.Info("refreshing tokens")

	userGUID, err := auth.GetCurrentUserGUID(ctx)
	if err != nil {
		log.Warn("missing user guid in context")
		return jwt.TokenPair{}, ErrUserNotFound
	}

	savedRefreshToken, err := auth.tokenRepo.GetRefreshTokenByUserGUID(ctx, userGUID)
	if err != nil {
		log.Error("failed to get refresh token from DB", err)
		return jwt.TokenPair{}, ErrInvalidToken
	}

	if time.Now().After(savedRefreshToken.ExpiresAt) {
		log.Warn("refresh token is expired")

		logoutError := auth.Logout(ctx)
		if logoutError != nil {
			log.Error("failed to logout", logoutError)
			return jwt.TokenPair{}, logoutError
		}

		return jwt.TokenPair{}, ErrInvalidToken
	}

	err = jwt.VerifyRefreshToken(refreshToken, savedRefreshToken.TokenHash)
	if err != nil {
		log.Error("failed to verify refresh token", err)

		logoutError := auth.Logout(ctx)
		if logoutError != nil {
			log.Error("failed to logout", logoutError)
			return jwt.TokenPair{}, logoutError
		}

		return jwt.TokenPair{}, ErrInvalidToken
	}

	sessionValue, exists := ctx.Get("session_id")
	if !exists {
		log.Warn("missing session_id in context")
		return jwt.TokenPair{}, ErrInvalidToken
	}

	sessionID, ok := sessionValue.(string)
	if !ok {
		log.Warn("invalid session_id in context")
		return jwt.TokenPair{}, ErrInvalidToken
	}

	if sessionID != savedRefreshToken.SessionID {
		log.Warn("invalid session_id in context")
		return jwt.TokenPair{}, ErrInvalidToken
	}

	incomingUserAgent := ctx.GetHeader("User-Agent")
	if incomingUserAgent != savedRefreshToken.UserAgent {
		log.Warn("user agent does not match")

		logoutError := auth.Logout(ctx)
		if logoutError != nil {
			log.Error("failed to logout", logoutError)
			return jwt.TokenPair{}, logoutError
		}

		return jwt.TokenPair{}, ErrInvalidToken
	}

	incomingIP := ctx.ClientIP()
	if incomingIP != savedRefreshToken.IP {
		go sendWebhook(webhookURL, userGUID, incomingIP, incomingUserAgent)
	}

	user, err := auth.userRepo.GetUserByGUID(ctx, userGUID)
	if err != nil {
		log.Error("failed to get user by GUID", err)
		return jwt.TokenPair{}, ErrUserNotFound
	}

	newTokenPair, err := jwt.NewTokenPair(user, auth.accessTokenTTL, auth.jwtSecret, savedRefreshToken.SessionID)
	if err != nil {
		log.Error("failed to generate token pair", err)
		return jwt.TokenPair{}, err
	}

	newRefreshToken := entity.RefreshToken{
		UserGUID:  user.GUID,
		TokenHash: newTokenPair.RefreshTokenHash,
		UserAgent: incomingUserAgent,
		IP:        incomingIP,
		SessionID: savedRefreshToken.SessionID,
		ExpiresAt: time.Now().Add(auth.refreshTokenTTL),
		CreatedAt: time.Now(),
	}

	if err := auth.tokenRepo.SaveToken(ctx, &newRefreshToken); err != nil {
		log.Error("failed to save refresh token", err)
		return jwt.TokenPair{}, err
	}

	log.Info("successfully refreshed token")

	return jwt.TokenPair{AccessToken: newTokenPair.AccessToken, RefreshToken: newTokenPair.RefreshToken, RefreshTokenHash: newTokenPair.RefreshTokenHash}, nil
}

func (auth *Auth) Logout(ctx *gin.Context) error {
	const op = "auth.Logout"

	log := auth.log.With(slog.String("op", op))

	userGUID, err := auth.GetCurrentUserGUID(ctx)
	if err != nil {
		log.Error("failed to get current user GUID in context", err)
		return ErrUserNotFound
	}

	err = auth.tokenRepo.DeleteTokenByUserGUID(ctx, userGUID)
	if err != nil {
		log.Error("failed to delete token by GUID in context", err)
		return err
	}

	log.Info("successfully logged out")

	return nil
}

func sendWebhook(url, userGUID, ip, userAgent string) {
	payload := map[string]string{
		"user_guid":  userGUID,
		"ip":         ip,
		"user_agent": userAgent,
		"time":       time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		slog.Error("sendWebhook: failed to marshal payload", slog.Any("error", err))
		return
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Error("sendWebhook: failed to send POST request", slog.Any("error", err))
		return
	}

	defer resp.Body.Close()
}

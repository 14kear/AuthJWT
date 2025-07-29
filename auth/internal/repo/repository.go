package repo

import (
	"errors"
	"github.com/14kear/TestingQuestionJWT/auth/internal/entity"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type Repo struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repo {
	return &Repo{db: db}
}

func (r *Repo) SaveToken(ctx *gin.Context, token *entity.RefreshToken) error {
	// удалим старые токены
	if err := r.DeleteTokenByUserGUID(ctx, token.UserGUID); err != nil {
		return err
	}
	return r.db.WithContext(ctx).Create(token).Error
}

func (r *Repo) GetRefreshTokenByUserGUID(ctx *gin.Context, guid string) (*entity.RefreshToken, error) {
	var token entity.RefreshToken
	if err := r.db.WithContext(ctx).Where("user_guid = ?", guid).Last(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *Repo) DeleteTokenByUserGUID(ctx *gin.Context, guid string) error {
	return r.db.WithContext(ctx).Where("user_guid = ?", guid).Delete(&entity.RefreshToken{}).Error
}

func (r *Repo) SaveUser(ctx *gin.Context, email string, passHash []byte) (string, error) {
	user := &entity.User{
		GUID:     uuid.NewString(),
		Email:    email,
		PassHash: passHash,
	}

	if err := r.db.WithContext(ctx).Create(user).Error; err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return "", ErrUserAlreadyExists
		}

		return "", err
	}

	return user.GUID, nil
}

func (r *Repo) GetUserByEmail(ctx *gin.Context, email string) (entity.User, error) {
	var user entity.User
	if err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return entity.User{}, ErrUserNotFound
		}
		return entity.User{}, err
	}
	return user, nil
}

func (r *Repo) GetUserByGUID(ctx *gin.Context, guid string) (entity.User, error) {
	var user entity.User
	if err := r.db.WithContext(ctx).Where("guid = ?", guid).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return entity.User{}, ErrUserNotFound
		}
		return entity.User{}, err
	}
	return user, nil
}

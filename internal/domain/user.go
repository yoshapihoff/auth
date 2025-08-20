package domain

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Common errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailExists        = errors.New("email already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrWeakPassword       = errors.New("password is too weak")
)

// User represents a user in the system
type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UserRepository defines the interface for user persistence operations
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)
	UpdateEmail(ctx context.Context, userID uuid.UUID, email string) error
	UpdatePasswordHash(ctx context.Context, userID uuid.UUID, passwordHash string) error
	Delete(ctx context.Context, id uuid.UUID) error
	CreateTables(ctx context.Context) error
}

// UserService defines the interface for user business logic
type UserService interface {
	Register(ctx context.Context, email, password, name string) (*User, error)
	Login(ctx context.Context, email, password string) (string, error)
	ValidateToken(ctx context.Context, tokenString string) (*User, error)
	GetProfile(ctx context.Context, userID uuid.UUID) (*User, error)
	UpdateEmail(ctx context.Context, userID uuid.UUID, email string) error
	UpdatePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}

// OAuthProvider defines the interface for OAuth authentication
type OAuthProvider interface {
	GetAuthURL(state string) string
	GetUserData(code string) (map[string]interface{}, error)
}

// OAuthService defines the interface for OAuth operations
type OAuthService interface {
	AuthCodeURL(provider, state string) (string, error)
	Exchange(ctx context.Context, provider, code string) (*User, error)
}

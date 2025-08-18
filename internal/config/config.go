package config

import (
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type DBConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
}

type JWTConfig struct {
	Secret     string
	Expiration time.Duration
}

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
}

type OAuthConfig struct {
	Google      OAuthProviderConfig
	GitHub      OAuthProviderConfig
	XCom        OAuthProviderConfig
	RedirectURL string
	SuccessURL  string
	ErrorURL    string
}

type Config struct {
	DB      DBConfig
	JWT     JWTConfig
	OAuth   OAuthConfig
	AppPort string
}

func Load() (*Config, error) {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found, using environment variables")
	}
	jwtExpiration, err := time.ParseDuration(getEnv("JWT_EXPIRATION", "24h"))
	if err != nil {
		return nil, err
	}

	// Initialize OAuth configuration
	oauthConfig := OAuthConfig{
		Google: OAuthProviderConfig{
			ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
			ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		},
		GitHub: OAuthProviderConfig{
			ClientID:     getEnv("GITHUB_CLIENT_ID", ""),
			ClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		},
		XCom: OAuthProviderConfig{
			ClientID:     getEnv("XCOM_CLIENT_ID", ""),
			ClientSecret: getEnv("XCOM_CLIENT_SECRET", ""),
		},
		RedirectURL: getEnv("OAUTH_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		SuccessURL:  getEnv("OAUTH_SUCCESS_URL", "http://localhost:3000/success"),
		ErrorURL:    getEnv("OAUTH_ERROR_URL", "http://localhost:3000/error"),
	}

	return &Config{
		DB: DBConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", "postgres"),
			Name:     getEnv("DB_NAME", "auth_service"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		JWT: JWTConfig{
			Secret:     getEnv("JWT_SECRET", "your-secret-key"),
			Expiration: jwtExpiration,
		},
		OAuth: oauthConfig,
		AppPort: getEnv("APP_PORT", "8080"),
	}, nil
}

// GetDSN returns the database connection string
func (c *DBConfig) GetDSN() string {
	return "postgres://" +
		c.User + ":" +
		c.Password + "@" +
		c.Host + ":" +
		c.Port + "/" +
		c.Name + "?sslmode=" +
		c.SSLMode
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/yourusername/auth/internal/auth"
	"github.com/yourusername/auth/internal/auth/oauth"
	"github.com/yourusername/auth/internal/config"
	"github.com/yourusername/auth/internal/db"
	httpHandler "github.com/yourusername/auth/internal/handler/http"
	postgresRepo "github.com/yourusername/auth/internal/repository/postgres"
	"github.com/yourusername/auth/internal/service"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	dbConn, err := db.Init(cfg.DB)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer dbConn.Close()

	// Create repositories
	userRepo := postgresRepo.NewUserRepository(dbConn)

	// Initialize JWT service
	jwtSvc := auth.NewJWTService(auth.JWTConfig{
		Secret: cfg.JWT.Secret,
	})

	// Initialize OAuth service
	oauthCfg := oauth.Config{
		Google: struct {
			ClientID     string
			ClientSecret string
			RedirectURL  string
		}{
			ClientID:     cfg.OAuth.Google.ClientID,
			ClientSecret: cfg.OAuth.Google.ClientSecret,
			RedirectURL:  cfg.OAuth.RedirectURL + "/callback/google",
		},
		GitHub: struct {
			ClientID     string
			ClientSecret string
			RedirectURL  string
		}{
			ClientID:     cfg.OAuth.GitHub.ClientID,
			ClientSecret: cfg.OAuth.GitHub.ClientSecret,
			RedirectURL:  cfg.OAuth.RedirectURL + "/callback/github",
		},
	}

	oauthSvc := oauth.NewService(oauthCfg)

	// Initialize services
	userSvc := service.NewUserService(userRepo, jwtSvc)

	// Create HTTP server
	r := mux.NewRouter()

	// Create handler
	handler := httpHandler.NewAuthHandler(userSvc, oauthSvc, jwtSvc)
	handler.RegisterRoutes(r)

	// Health check endpoint
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")

	// Start server
	srv := &http.Server{
		Addr:         ":" + cfg.AppPort,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	// Run server in a goroutine
	go func() {
		log.Printf("Server is running on http://localhost%s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not start server: %v\n", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv.SetKeepAlivesEnabled(false)
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Could not gracefully shutdown the server: %v\n", err)
	}

	log.Println("Server stopped")
}

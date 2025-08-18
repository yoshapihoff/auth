package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/yourusername/auth/internal/auth"
	"github.com/yourusername/auth/internal/auth/oauth"
	"github.com/yourusername/auth/internal/domain"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	Data interface{} `json:"data"`
}

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
	Name     string `json:"name" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	Token string      `json:"token"`
	User  *domain.User `json:"user"`
}

type UpdateProfileRequest struct {
	Name string `json:"name" validate:"required"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

type OAuthStartResponse struct {
	URL string `json:"url"`
}

type OAuthCallbackResponse struct {
	Token string      `json:"token"`
	User  *domain.User `json:"user"`
}

type AuthHandler struct {
	userService domain.UserService
	jwtSvc     *auth.JWTService
	oauthSvc   *oauth.Service
}

func NewAuthHandler(userService domain.UserService, oauthSvc *oauth.Service, jwtSvc *auth.JWTService) *AuthHandler {
	return &AuthHandler{
		userService: userService,
		jwtSvc:     jwtSvc,
		oauthSvc:   oauthSvc,
	}
}

func (h *AuthHandler) RegisterRoutes(router *mux.Router) {
	authRouter := router.PathPrefix("/auth").Subrouter()

	// Public routes
	authRouter.HandleFunc("/register", h.handleRegister).Methods("POST")
	authRouter.HandleFunc("/login", h.handleLogin).Methods("POST")
	authRouter.HandleFunc("/oauth/{provider}", h.handleOAuthStart).Methods("GET")
	authRouter.HandleFunc("/oauth/{provider}/callback", h.handleOAuthCallback).Methods("GET")

	// Protected routes
	protected := authRouter.PathPrefix("/me").Subrouter()
	protected.Use(h.authMiddleware)
	protected.HandleFunc("", h.handleGetProfile).Methods("GET")
	protected.HandleFunc("", h.handleUpdateProfile).Methods("PUT")
	protected.HandleFunc("/password", h.handleChangePassword).Methods("PUT")
}

func (h *AuthHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Register the user
	user, err := h.userService.Register(r.Context(), req.Email, req.Password, req.Name)
	if err != nil {
		handleError(w, err)
		return
	}

	// Generate JWT token
	token, err := h.jwtSvc.GenerateToken(user.ID, user.Email)
	if err != nil {
		handleError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusCreated, &LoginResponse{
		Token: token,
		User:  user,
	})
}

func (h *AuthHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.userService.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		handleError(w, err)
		return
	}

	user, err := h.userService.ValidateToken(r.Context(), token)
	if err != nil {
		handleError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, &LoginResponse{
		Token: token,
		User:  user,
	})
}

func (h *AuthHandler) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.userService.GetProfile(r.Context(), userID)
	if err != nil {
		handleError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, user)
}

func (h *AuthHandler) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.userService.UpdateProfile(r.Context(), userID, req.Name); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(uuid.UUID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.userService.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		handleError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	provider := mux.Vars(r)["provider"]
	state := uuid.New().String()

	// Store state in session or secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})

	url, err := h.oauthSvc.GetAuthURL(provider, state)
	if err != nil {
		handleError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, &OAuthStartResponse{
		URL: url,
	})
}

func (h *AuthHandler) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("oauth_state")
	if err != nil || cookie.Value != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	provider := mux.Vars(r)["provider"]
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "authorization code not found", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	token, err := h.oauthSvc.ExchangeCode(r.Context(), provider, code)
	if err != nil {
		handleError(w, fmt.Errorf("failed to exchange code: %v", err))
		return
	}

	// Get user info
	userInfo, err := h.oauthSvc.GetUserInfo(r.Context(), provider, token)
	if err != nil {
		handleError(w, fmt.Errorf("failed to get user info: %v", err))
		return
	}

	// Extract email and name from user info
	email := userInfo.Email
	name := userInfo.Name
	if name == "" {
		name = userInfo.Username // Fallback for GitHub
	}

	if email == "" {
		handleError(w, fmt.Errorf("email is required but not provided by the OAuth provider"))
		return
	}

	// Check if user exists
	user, err := h.userService.GetUserByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		handleError(w, err)
		return
	}

	// Create new user if not exists
	if user == nil {
		// Generate a random password for OAuth users
		password := uuid.New().String()
		user, err = h.userService.Register(r.Context(), email, password, name)
		if err != nil {
			handleError(w, err)
			return
		}
	}

	// Generate JWT token
	tokenString, err := h.jwtSvc.GenerateToken(user.ID, user.Email)
	if err != nil {
		handleError(w, err)
		return
	}

	h.respondWithJSON(w, http.StatusOK, &OAuthCallbackResponse{
		Token: tokenString,
		User:  user,
	})
}

func (h *AuthHandler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "authorization header is required", http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[len("Bearer "):]
		if tokenString == "" {
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		user, err := h.userService.ValidateToken(r.Context(), tokenString)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Add user to context
		ctx := context.WithValue(r.Context(), "userID", user.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *AuthHandler) respondWithJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if data != nil {
		err := json.NewEncoder(w).Encode(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func handleError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError

	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		status = http.StatusNotFound
	case errors.Is(err, domain.ErrEmailExists):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrInvalidCredentials):
		status = http.StatusUnauthorized
	case errors.Is(err, domain.ErrWeakPassword):
		status = http.StatusBadRequest
	}

	http.Error(w, err.Error(), status)
}

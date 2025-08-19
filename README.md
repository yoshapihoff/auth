# Authentication Service

A scalable authentication service built with Go, PostgreSQL, and JWT, supporting both email/password and OAuth2 authentication.

## Features

- User registration and login with email/password
- JWT-based authentication
- OAuth2 integration (Google, GitHub)
- Password hashing using bcrypt
- RESTful API
- Horizontal scalability
- Clean architecture with dependency injection

## Prerequisites

- Go 1.21 or higher
- PostgreSQL 12 or higher
- Git

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/auth.git
   cd auth
   ```

2. Copy the example environment file and update the values:
   ```bash
   cp .env.example .env
   ```

3. Update the `.env` file with your database credentials and other settings.

4. Install dependencies:
   ```bash
   go mod download
   ```

5. Run migrations (tables will be created automatically on first run):
   ```bash
   go run cmd/api/main.go
   ```

6. The server will start on `http://localhost:8080`

## API Endpoints

### Authentication

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login with email and password
- `GET /auth/oauth/{provider}` - Start OAuth flow (google, github)
- `GET /auth/oauth/{provider}/callback` - OAuth callback URL

### User Profile (Requires Authentication)

- `GET /auth/me` - Get current user profile
- `PUT /auth/me` - Update profile
- `PUT /auth/me/password` - Change password

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | Database host | localhost |
| `DB_PORT` | Database port | 5432 |
| `DB_USER` | Database user | postgres |
| `DB_PASSWORD` | Database password | postgres |
| `DB_NAME` | Database name | auth_service |
| `DB_SSLMODE` | SSL mode for database | disable |
| `JWT_SECRET` | Secret key for JWT signing | your-secret-key |
| `JWT_EXPIRATION` | JWT expiration duration | 24h |
| `GOOGLE_OAUTH_CLIENT_ID` | Google OAuth client ID | |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Google OAuth client secret | |
| `GITHUB_OAUTH_CLIENT_ID` | GitHub OAuth client ID | |
| `GITHUB_OAUTH_CLIENT_SECRET` | GitHub OAuth client secret | |
| `OAUTH_REDIRECT_URL` | OAuth callback URL | http://localhost:8080/oauth/callback |
| `OAUTH_SUCCESS_URL` | URL to redirect after successful OAuth login | http://localhost:3000/login/success |
| `OAUTH_ERROR_URL` | URL to redirect after OAuth error | http://localhost:3000/login/error |
| `SERVER_READ_TIMEOUT` | Maximum duration for reading the request | 10s |
| `SERVER_WRITE_TIMEOUT` | Maximum duration for writing the response | 10s |
| `SERVER_IDLE_TIMEOUT` | Maximum duration for idle connections | 15s |

## Running Tests

```bash
go test -v ./...
```

## Server Configuration

The service includes the following server configurations with their default values:

- **Read Timeout**: 10 seconds - Maximum duration for reading the entire request
- **Write Timeout**: 10 seconds - Maximum duration before timing out writes of the response
- **Idle Timeout**: 15 seconds - Maximum amount of time to wait for the next request when keep-alives are enabled

These values can be configured using the environment variables mentioned above.

## Deployment

### Docker

1. Build the Docker image:
   ```bash
   docker build -t auth-service .
   ```

2. Run the container:
   ```bash
   docker run -p 8080:8080 --env-file .env auth-service
   ```

### Kubernetes

Example Kubernetes deployment files are provided in the `k8s/` directory.

## Scaling

The service is stateless and can be scaled horizontally. Use a load balancer to distribute traffic between instances.

## Contributing

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

MIT

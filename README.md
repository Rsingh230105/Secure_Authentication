# Secure Authentication API

## Project Overview

A production-style secure authentication backend built with FastAPI, featuring JWT authentication, refresh token rotation, OTP-based passwordless login, email verification, password reset, and protected API routes. Designed for clarity, security, and maintainability.

---

## Tech Stack

- Python 3.13
- FastAPI
- PostgreSQL
- SQLAlchemy ORM
- Alembic
- Pydantic v2
- pydantic-settings
- Passlib (bcrypt)
- python-jose (JWT)
- Uvicorn

---

## Implemented Features

### User Authentication
- User registration with duplicate email detection
- Secure password hashing using bcrypt
- OAuth2 Password Flow login
- JWT access token generation
- Refresh token handling with rotation and revocation

### Protected Routes
- OAuth2/JWT authentication dependency
- Protected user profile endpoint: `GET /api/v1/users/me`

### Email Authentication
- Email verification flow (token-based)
- Forgot password request
- Password reset using a secure token

### OTP Authentication
- Request a one-time password delivered via email
- Verify OTP and complete passwordless login
- JWT access and refresh token pair issued after OTP login

### Database
- PostgreSQL integration
- SQLAlchemy ORM models
- Alembic migrations

---

## Project Structure

```
app/
├── api/          # Route handlers (versioned)
├── core/         # Configuration and settings
├── database/     # Database session and engine setup
├── models/       # SQLAlchemy ORM models
├── schemas/      # Pydantic request/response schemas
├── services/     # Business logic (auth, OTP, email)
└── utils/        # Shared utilities
```

---

## Installation Setup

### Clone the repository

```bash
git clone <repository-url>
cd secure_auth
```

### Create and activate a virtual environment

**Windows:**
```powershell
python -m venv venv
venv\Scripts\activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Environment Configuration

Copy `.env.example` to `.env` and fill in your local values. Never commit secrets to version control.

```bash
cp .env.example .env
```

Required variables:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `SECRET_KEY` | Secret key used for JWT signing |
| `JWT_ALGORITHM` | Algorithm for JWT (e.g. `HS256`) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Access token lifetime in minutes |
| `REFRESH_TOKEN_EXPIRE_DAYS` | Refresh token lifetime in days |

---

## Database Migration

Apply all Alembic migrations to set up the database schema:

```bash
alembic upgrade head
```

---

## Run Application

```bash
uvicorn main:app --reload
```

---

## API Documentation

FastAPI provides interactive Swagger documentation at:

```
http://127.0.0.1:8000/docs
```

### Endpoints

**Authentication**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/register` | Register a new user |
| `POST` | `/api/v1/auth/login` | Login via OAuth2 password form |
| `POST` | `/api/v1/auth/refresh` | Rotate a refresh token |

**Email**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/verify-email` | Verify email using a token |
| `POST` | `/api/v1/auth/forgot-password` | Request a password reset email |
| `POST` | `/api/v1/auth/reset-password` | Reset password using a token |

**OTP**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/request-otp` | Request a one-time password |
| `POST` | `/api/v1/auth/login-otp` | Login using a one-time password |

**Users**

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/users/me` | Get authenticated user profile |

---

## Authentication Flow

**Standard Registration & Login**
```
Register → Password Hashing → Login (OAuth2) → JWT Access Token → Protected API
```

**OTP Passwordless Login**
```
Request OTP → OTP delivered via email → Verify OTP → JWT Access Token → Protected API
```

**Token Refresh**
```
Submit Refresh Token → Token Validated & Rotated → New Access + Refresh Token Pair
```

---

## Security Implementation

- bcrypt password hashing via Passlib
- JWT access token validation on every protected request
- Refresh token rotation — each token is single-use and revoked after rotation
- Environment-based configuration — no secrets in source code
- Pydantic v2 input validation on all request bodies
- Anti-enumeration responses on forgot-password and request-otp endpoints
- CORS configuration via FastAPI middleware

---

## Testing Guide

Use the Swagger UI at `http://127.0.0.1:8000/docs` to test all endpoints interactively:

1. **Register** — `POST /api/v1/auth/register` with email and password
2. **Login** — `POST /api/v1/auth/login` using the OAuth2 form (Authorize button)
3. **Authorize** — paste the returned JWT access token into the Swagger Authorize dialog
4. **Access protected route** — `GET /api/v1/users/me` to confirm authentication works
5. **Test OTP flow** — call `POST /api/v1/auth/request-otp`, retrieve the OTP from your email (or terminal in dev mode), then call `POST /api/v1/auth/login-otp` to receive a token pair

package data

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// Token scopes define the purpose of the token.
const (
	ScopeActivation     = "activation"     // Token for account activation.
	ScopeAuthentication = "authentication" // Token for user authentication.
)

// Token represents a user's token with associated metadata.
type Token struct {
	Plaintext string    `json:"token"`  // Unhashed token visible to the client.
	Hash      []byte    `json:"-"`      // Hashed version stored securely.
	UserID    int64     `json:"-"`      // ID of the associated user.
	Expiry    time.Time `json:"expiry"` // Token expiration timestamp.
	Scope     string    `json:"-"`      // Token's purpose or scope.
}

// generateToken creates a new token for a user with a specific scope and TTL.
func generateToken(userID int64, ttl time.Duration, scope string) (*Token, error) {
	// Initialize the token with user ID, expiry, and scope.
	token := &Token{
		UserID: userID,
		Expiry: time.Now().Add(ttl),
		Scope:  scope,
	}

	// Generate 16 random bytes.
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	// Encode the random bytes to a base-32 string without padding.
	token.Plaintext = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)

	// Hash the plaintext token for secure storage.
	hash := sha256.Sum256([]byte(token.Plaintext))
	token.Hash = hash[:] // Convert array to slice.

	return token, nil
}

// ValidateTokenPlaintext checks if a provided token is valid and 26 characters long.
func ValidateTokenPlaintext(v *validator.Validator, tokenPlaintext string) {
	v.Check(tokenPlaintext != "", "token", "must be provided")           // Ensure token is not empty.
	v.Check(len(tokenPlaintext) == 26, "token", "must be 26 bytes long") // Verify correct length.
}

// TokenModel provides methods for managing tokens in the database.
type TokenModel struct {
	DB *sql.DB // Database connection pool.
}

// New creates a new token, saves it in the database, and returns it.
func (t TokenModel) New(userID int64, ttl time.Duration, scope string) (*Token, error) {
	// Generate a new token for the user.
	token, err := generateToken(userID, ttl, scope)
	if err != nil {
		return nil, err
	}

	// Insert the token into the database.
	err = t.Insert(token)
	return token, err
}

// Insert saves the token into the database.
func (t TokenModel) Insert(token *Token) error {
	query := `
              INSERT INTO tokens (hash, user_id, expiry, scope) 
              VALUES ($1, $2, $3, $4)
            `
	// Arguments for the SQL query.
	args := []any{token.Hash, token.UserID, token.Expiry, token.Scope}

	// Use a context with a timeout to prevent long-running queries.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := t.DB.ExecContext(ctx, query, args...)
	return err
}

// DeleteAllForUser removes all tokens for a specific user and scope.
func (t TokenModel) DeleteAllForUser(scope string, userID int64) error {
	query := `
            DELETE FROM tokens 
            WHERE scope = $1 AND user_id = $2
			`
	// Context with a timeout for safety.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := t.DB.ExecContext(ctx, query, scope, userID)
	return err
}

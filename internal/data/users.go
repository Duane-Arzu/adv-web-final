package data

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/Duane-Arzu/adv-web-final.git/internal/validator"
	"golang.org/x/crypto/bcrypt"
)

var AnonymousUser = &User{}

type User struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  password  `json:"-"` // Password field, hidden in JSON
	Activated bool      `json:"activated"`
	Version   int       `json:"-"` // Tracks row version for concurrency
}

type UserReview struct {
	ReviewID   int64     `json:"id"`      // Primary key
	BookID     int64     `json:"book_id"` // Foreign key for book
	Rating     int64     `json:"rating"`  // Rating (1-5)
	ReviewText string    `json:"review"`  // Review content
	ReviewDate time.Time `json:"-"`       // Auto-set timestamp
	Version    int       `json:"version"`
}

type UserList struct {
	ID          int64  `json:"id"`          // Primary key
	Name        string `json:"name"`        // List name
	Description string `json:"description"` // List description
	CreatedBy   int    `json:"created_by"`  // Creator's user ID
	Version     int    `json:"version"`     // Row version
}

// Encapsulates plaintext and hashed passwords.
type password struct {
	plaintext *string
	hash      []byte
}

type UserModel struct {
	DB *sql.DB
}

// Checks if a user is anonymous.
func (u *User) IsAnonymous() bool {
	return u == AnonymousUser
}

// Hashes and stores a plaintext password.
func (p *password) Set(plaintextPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), 12)
	if err != nil {
		return err
	}
	p.plaintext = &plaintextPassword
	p.hash = hash
	return nil
}

// Verifies a password against the stored hash.
func (p *password) Matches(plaintextPassword string) (bool, error) {
	err := bcrypt.CompareHashAndPassword(p.hash, []byte(plaintextPassword))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Validates email format and presence.
func ValidateEmail(v *validator.Validator, email string) {
	v.Check(email != "", "email", "must be provided")
	v.Check(validator.Matches(email, validator.EmailRX), "email", "must be valid")
}

// Validates password length and presence.
func ValidatePasswordPlaintext(v *validator.Validator, password string) {
	v.Check(password != "", "password", "must be provided")
	v.Check(len(password) >= 8, "password", "must be at least 8 characters")
	v.Check(len(password) <= 72, "password", "must be at most 72 characters")
}

// Validates user fields and relationships.
func ValidateUser(v *validator.Validator, user *User) {
	v.Check(user.Username != "", "username", "must be provided")
	v.Check(len(user.Username) <= 200, "username", "max length is 200")
	ValidateEmail(v, user.Email)
	if user.Password.plaintext != nil {
		ValidatePasswordPlaintext(v, *user.Password.plaintext)
	}
	if user.Password.hash == nil {
		panic("missing password hash for user")
	}
}

// Adds a new user to the database.
func (u UserModel) Insert(user *User) error {
	query := `
		INSERT INTO users (created_at, username, email, password_hash, activated, version)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, version
	`
	args := []interface{}{
		time.Now(), user.Username, user.Email, user.Password.hash, user.Activated, user.Version,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := u.DB.QueryRowContext(ctx, query, args...).Scan(&user.ID, &user.CreatedAt, &user.Version)
	if err != nil {
		if err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"` {
			return ErrDuplicateEmail
		}
		return err
	}
	return nil
}

// Fetches a user by email.
func (u UserModel) GetByEmail(email string) (*User, error) {
	query := `
	SELECT id, created_at, username, email, password_hash, activated, version
	FROM users WHERE email = $1
   `
	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := u.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.CreatedAt, &user.Username, &user.Email, &user.Password.hash, &user.Activated, &user.Version,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}
	return &user, nil
}

// Updates user information in the database.
func (u UserModel) Update(user *User) error {
	query := `
		UPDATE users 
		SET username = $1, email = $2, password_hash = $3, activated = $4, version = version + 1
		WHERE id = $5 AND version = $6
		RETURNING version
	`
	args := []interface{}{user.Username, user.Email, user.Password.hash, user.Activated, user.ID, user.Version}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := u.DB.QueryRowContext(ctx, query, args...).Scan(&user.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEditConflict
		}
		return err
	}
	return nil
}

// Gets user by token for authentication.
func (u UserModel) GetForToken(tokenScope, tokenPlaintext string) (*User, error) {
	tokenHash := sha256.Sum256([]byte(tokenPlaintext))
	query := `
        SELECT users.id, users.created_at, users.username, users.email, users.password_hash, users.activated, users.version
        FROM users INNER JOIN tokens ON users.id = tokens.user_id
        WHERE tokens.hash = $1 AND tokens.scope = $2 AND tokens.expiry > $3
       `
	args := []any{tokenHash[:], tokenScope, time.Now()}
	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := u.DB.QueryRowContext(ctx, query, args...).Scan(
		&user.ID, &user.CreatedAt, &user.Username, &user.Email, &user.Password.hash, &user.Activated, &user.Version,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}
	return &user, nil
}

// Retrieves a user by ID.
func (u *UserModel) GetByID(id int64) (*User, error) {
	query := `
	SELECT id, created_at, username, email, activated, version
	FROM users WHERE id = $1
	`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var user User
	err := u.DB.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.CreatedAt, &user.Username, &user.Email, &user.Activated, &user.Version,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}
	return &user, nil
}

// Fetches reviews for a user.
func (u *UserModel) GetUserReviews(userID int64) ([]UserReview, error) {
	query := `SELECT id, book_id, rating, review, review_date, version FROM bookreviews WHERE user_id = $1`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := u.DB.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reviews []UserReview
	for rows.Next() {
		var review UserReview
		err := rows.Scan(&review.ReviewID, &review.BookID, &review.Rating, &review.ReviewText, &review.ReviewDate, &review.Version)
		if err != nil {
			return nil, err
		}
		reviews = append(reviews, review)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return reviews, nil
}

// Fetches lists created by a user.
func (u *UserModel) GetUserLists(userID int64) ([]UserList, error) {
	query := `SELECT id, name, description, created_by, version FROM readinglists WHERE created_by = $1`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := u.DB.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var lists []UserList
	for rows.Next() {
		var list UserList
		err := rows.Scan(&list.ID, &list.Name, &list.Description, &list.CreatedBy, &list.Version)
		if err != nil {
			return nil, err
		}
		lists = append(lists, list)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return lists, nil
}

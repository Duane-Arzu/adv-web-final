package data

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/validator"
	"golang.org/x/crypto/bcrypt"
)

var AnonymousUser = &User{}

type User struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Password  password  `json:"-"`
	Activated bool      `json:"activated"`
	Version   int       `json:"-"`
}

type UserReview struct {
	ReviewID   int64     `json:"id"`      // bigserial primary key
	BookID     int64     `json:"book_id"` // foreign key referencing products
	Rating     int64     `json:"rating"`  // integer with a constraint (1-5)
	ReviewText string    `json:"review"`  // non-null text field
	ReviewDate time.Time `json:"-"`       // timestamp with timezone, default now()
	Version    int       `json:"version"`
}

type UserList struct {
	ID          int64  `json:"id"`          // Maps to 'id' in SQL
	Name        string `json:"name"`        // Maps to 'name' in SQL
	Description string `json:"description"` // Maps to 'description' in SQL
	CreatedBy   int    `json:"created_by"`  // Maps to 'created_by' in SQL
	Version     int    `json:"version"`     // Maps to 'version' in SQL
}

// Define the password type (plaintext + hashed password).
// Lowercase because we do not want it to be public.
type password struct {
	plaintext *string
	hash      []byte
}

type UserModel struct {
	DB *sql.DB
}

func (u *User) IsAnonymous() bool {
	return u == AnonymousUser
}

// The Set() method computes the hash of the password.
func (p *password) Set(plaintextPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), 12)
	if err != nil {
		return err
	}
	p.plaintext = &plaintextPassword
	p.hash = hash
	return nil
}

// Compare the client-provided plaintext password with saved-hashed version.
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

func ValidateEmail(v *validator.Validator, email string) {
	v.Check(email != "", "email", "must be provided")
	v.Check(validator.Matches(email, validator.EmailRX), "email", "must be a valid email address")
}

// Check that a valid password is provided.
func ValidatePasswordPlaintext(v *validator.Validator, password string) {
	v.Check(password != "", "password", "must be provided")
	v.Check(len(password) >= 8, "password", "must be at least 8 bytes long")
	v.Check(len(password) <= 72, "password", "must not be more than 72 bytes long")
}

func ValidateUser(v *validator.Validator, user *User) {
	v.Check(user.Username != "", "username", "must be provided")
	v.Check(len(user.Username) <= 200, "username", "must not be more than 200 bytes long")
	ValidateEmail(v, user.Email)
	if user.Password.plaintext != nil {
		ValidatePasswordPlaintext(v, *user.Password.plaintext)
	}
	if user.Password.hash == nil {
		panic("missing password hash for user")
	}
}

// Insert a new user into the database.
func (u UserModel) Insert(user *User) error {
	query := `
		INSERT INTO users (created_at, username, email, password_hash, activated, version)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, version
	`
	args := []interface{}{
		time.Now(),
		user.Username,
		user.Email,
		user.Password.hash,
		user.Activated,
		user.Version,
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

func (u UserModel) GetByEmail(email string) (*User, error) {
	query := `
	SELECT id, created_at, username, email, password_hash, activated, version
	FROM users
	WHERE email = $1
   `
	var user User

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := u.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Username,
		&user.Email,
		&user.Password.hash,
		&user.Activated,
		&user.Version,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

// Update an existing user in the database.
func (u UserModel) Update(user *User) error {
	query := `
		UPDATE users 
		SET username = $1, email = $2, password_hash = $3,
			activated = $4, version = version + 1
		WHERE id = $5 AND version = $6
		RETURNING version
	`
	args := []interface{}{
		user.Username,
		user.Email,
		user.Password.hash,
		user.Activated,
		user.ID,
		user.Version,
	}

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

func (u UserModel) GetForToken(tokenScope, tokenPlaintext string) (*User, error) {
	tokenHash := sha256.Sum256([]byte(tokenPlaintext))

	query := `
        SELECT users.id, users.created_at, users.username,
               users.email, users.password_hash, users.activated, users.version
        FROM users
        INNER JOIN tokens
        ON users.id = tokens.user_id
        WHERE tokens.hash = $1
        AND tokens.scope = $2 
        AND tokens.expiry > $3
       `
	args := []any{tokenHash[:], tokenScope, time.Now()}
	var user User
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := u.DB.QueryRowContext(ctx, query, args...).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Username,
		&user.Email,
		&user.Password.hash,
		&user.Activated,
		&user.Version,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	return &user, nil
}

func (u *UserModel) GetByID(id int64) (*User, error) {
	query := `
	SELECT id, created_at, username, email, activated, version
	FROM users
	WHERE id = $1
	`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var user User
	err := u.DB.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.Username,
		&user.Email,
		&user.Activated,
		&user.Version,
	)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

func (u *UserModel) GetUserReviews(userID int64) ([]UserReview, error) {
	query := `
	SELECT id, book_id, rating, review, review_date, version
	FROM bookreviews
	WHERE user_id = $1
	`
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
		err := rows.Scan(
			&review.ReviewID,
			&review.BookID,
			&review.Rating,
			&review.ReviewText,
			&review.ReviewDate,
			&review.Version,
		)
		if err != nil {
			return nil, err
		}
		reviews = append(reviews, review)
	}

	// Check for any errors encountered during iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return reviews, nil
}

func (u *UserModel) GetUserLists(userID int64) ([]UserList, error) {
	query := `
	SELECT id, name, description, created_by, version
	FROM readinglists
	WHERE created_by = $1
	`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := u.DB.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var lists []UserList // Ensure the type here matches the return type
	for rows.Next() {
		var list UserList // Change to UserReview if that matches your expected structure
		err := rows.Scan(
			&list.ID,
			&list.Name,
			&list.Description,
			&list.CreatedBy,
			&list.Version,
		)
		if err != nil {
			return nil, err
		}
		lists = append(lists, list)
	}

	// Check for any errors encountered during iteration
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return lists, nil
}

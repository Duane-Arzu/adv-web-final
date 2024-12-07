// Filename: internal/data/reviews.go
package data

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// Review struct
type Review struct {
	ReviewID   int64     `json:"id"`
	BookID     int64     `json:"book_id"`
	UserID     int64     `json:"user_id"`
	Rating     int64     `json:"rating"`
	ReviewText string    `json:"review"`
	ReviewDate time.Time `json:"-"`
	Version    int       `json:"version"`
}

type ReviewModel struct {
	DB *sql.DB
}

func ValidateReview(v *validator.Validator, review *Review) {
	v.Check(review.UserID > 0, "user_id", "must be provided")
	v.Check(review.ReviewText != "", "review_text", "must be provided")

	v.Check(review.BookID > 0, "book_id", "must be a positive integer")

	v.Check(review.Rating >= 1 && review.Rating <= 5, "rating", "must be between 1 and 5")
}

func (c ReviewModel) InsertReview(review *Review) error {
	query := `
		INSERT INTO bookreviews (book_id, user_id, rating, review)
		VALUES ($1, $2, $3, $4)
		RETURNING id, review_date, version
	`
	args := []any{review.BookID, review.UserID, review.Rating, review.ReviewText}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.DB.QueryRowContext(ctx, query, args...).Scan(
		&review.ReviewID,
		&review.ReviewDate,
		&review.Version)
}
func (c ReviewModel) GetReview(id int64) (*Review, error) {
	if id < 1 {
		return nil, ErrRecordNotFound
	}
	query := `
		SELECT  id, book_id, user_id, rating, review, review_date, version
		FROM bookreviews
		WHERE id = $1
	`
	var review Review

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := c.DB.QueryRowContext(ctx, query, id).Scan(
		&review.ReviewID,
		&review.BookID,
		&review.UserID,
		&review.Rating,
		&review.ReviewText,
		&review.ReviewDate,
		&review.Version,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRecordNotFound
		}
		return nil, err
	}
	return &review, nil
}

func (c ReviewModel) GetAllBookReviews(bookID int64) ([]*Review, error) {
	if bookID < 1 {
		return nil, ErrRecordNotFound
	}

	query := `
		SELECT id, book_id, user_id, rating, review, review_date, version
		FROM bookreviews
		WHERE book_id = $1
		ORDER BY review_date DESC
	`

	var reviews []*Review

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := c.DB.QueryContext(ctx, query, bookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var review Review
		err := rows.Scan(
			&review.ReviewID,
			&review.BookID,
			&review.UserID,
			&review.Rating,
			&review.ReviewText,
			&review.ReviewDate,
			&review.Version,
		)
		if err != nil {
			return nil, err
		}
		reviews = append(reviews, &review)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return reviews, nil
}

func (c ReviewModel) UpdateReview(review *Review) error {
	query := `
		UPDATE bookreviews
		SET  rating = $1, review = $2, version = version + 1
		WHERE id = $3
		RETURNING version
	`

	args := []any{review.Rating, review.ReviewText, review.ReviewID}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.DB.QueryRowContext(ctx, query, args...).Scan(&review.Version)
}

func (c ReviewModel) DeleteReview(id int64) error {
	if id < 1 {
		return ErrRecordNotFound
	}
	query := `
		DELETE FROM bookreviews
		WHERE id = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := c.DB.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	return nil
}

func (m *BookModel) BookExists(productID int64) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM books WHERE id = $1)`
	var exists bool
	err := m.DB.QueryRow(query, productID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (m *ReviewModel) Exists(id int64) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM bookreviews WHERE id = $1)`
	err := m.DB.QueryRow(query, id).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Filename: internal/data/books.go
package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// each name begins with uppercase so that they are exportable/public

type Book struct {
	ID              int64   `json:"id"` // bigserial maps to int64
	Title           string  `json:"title"`
	Authors         string  `json:"authors"`          // TEXT[] maps to a slice of strings
	ISBN            string  `json:"isbn"`             // Optional field, use a pointer to handle NULL
	PublicationDate string  `json:"publication_date"` // DATE maps to *time.Time for optional values
	Genre           string  `json:"genre"`            // Optional field, use a pointer to handle NULL
	Description     string  `json:"description"`      // Optional field, use a pointer to handle NULL
	AverageRating   float32 `json:"average_rating"`   // DECIMAL maps to float64
	Version         int32   `json:"version"`          // Default field for versioning
}

type BookModel struct {
	DB *sql.DB
}

// Example Exists method in bookModel
func (m *BookModel) Exists(bookID int) (bool, error) {
	var exists bool
	query := "SELECT EXISTS (SELECT 1 FROM books WHERE id = $1)"
	err := m.DB.QueryRow(query, bookID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func ValidateBook(v *validator.Validator, book *Book) {
	// Validate the Title field
	v.Check(strings.TrimSpace(book.Title) != "", "title", "must be provided")
	v.Check(len(book.Title) <= 200, "title", "must not be more than 200 bytes long")

	// Validate the Authors field
	v.Check(strings.TrimSpace(book.Authors) != "", "authors", "must be provided")
	v.Check(len(book.Authors) <= 200, "authors", "must not be more than 200 bytes long")

	v.Check(strings.TrimSpace(book.ISBN) != "", "isbn", "must be provided")
	v.Check(len(book.ISBN) == 13, "isbn", "must be 13 digits long")
	v.Check(regexp.MustCompile(`^\d{13}$`).MatchString(book.ISBN), "isbn", "must contain only digits")

	// Check if the publication date is provided
	v.Check(strings.TrimSpace(book.PublicationDate) != "", "publication_date", "must be provided")

	// Regular expression to match the format "July 12, 2024"
	dateRegex := `^[A-Za-z]+ \d{1,2}, \d{4}$`
	re := regexp.MustCompile(dateRegex)

	// Check if the date matches the regex
	if !re.MatchString(book.PublicationDate) {
		v.AddError("publication_date", "must be in the format 'July 12, 2020'")
	}

	// Check if the length of the publication date is less than or equal to 200
	v.Check(len(book.PublicationDate) <= 200, "publication_date", "must not be more than 200 bytes long")

	v.Check(strings.TrimSpace(book.Genre) != "", "genre", "must be provided")
	v.Check(len(book.Genre) <= 200, "genre", "must not be more than 200 bytes long")

	// Validate the Description field
	v.Check(strings.TrimSpace(book.Description) != "", "description", "must be provided")
	v.Check(len(book.Description) <= 200, "description", "must not be more than 200 bytes long")

}

func (c BookModel) Insert(book *Book) error {
	// the SQL query to be executed against the database table
	query := `
	INSERT INTO books (title, authors, isbn, publication_date, genre, description) 
	VALUES ($1, $2, $3, $4, $5, $6) 
	RETURNING id, version;
		 `
	// the actual values to replace $1, and $2
	args := []any{book.Title, book.Authors, book.ISBN, book.PublicationDate, book.Genre, book.Description}

	// Create a context with a 3-second timeout. No database
	// operation should take more than 3 seconds or we will quit it
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// execute the query against the comments database table. We ask for the the
	// id, created_at, and version to be sent back to us which we will use
	// to update the Comment struct later on
	return c.DB.QueryRowContext(ctx, query, args...).Scan(
		&book.ID,
		&book.Version)
}

// Get a specific Comment from the comments table
func (c BookModel) Get(id int64) (*Book, error) {
	// check if the id is valid
	if id < 1 {
		return nil, ErrRecordNotFound
	}
	// the SQL query to be executed against the database table
	query := `
		 SELECT  id, title, authors, isbn, publication_date, genre, description, average_rating, version
		 FROM books
		 WHERE id = $1
	   `
	// declare a variable of type Comment to store the returned comment
	var book Book

	// Set a 3-second context/timer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := c.DB.QueryRowContext(ctx, query, id).Scan(
		&book.ID,
		&book.Title,
		&book.Authors, // pq.Array handles TEXT[] types
		&book.ISBN,
		&book.PublicationDate,
		&book.Genre,
		&book.Description,
		&book.AverageRating,
		&book.Version,
	)
	// Cont'd on the next slide
	// check for which type of error
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, ErrRecordNotFound
		default:
			return nil, err
		}
	}
	return &book, nil
}

func (c BookModel) Update(book *Book) error {
	// The SQL query to be executed against the database table
	// Every time we make an update, we increment the version number
	query := `
			UPDATE books
			SET  title = $1, authors = $2, isbn = $3, publication_date = $4, genre = $5, description = $6, version = version + 1
			WHERE id = $7
			RETURNING version 
			`

	args := []any{book.Title, book.Authors, book.ISBN, book.PublicationDate, book.Genre, book.Description, book.ID}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.DB.QueryRowContext(ctx, query, args...).Scan(&book.Version)

}

func (c BookModel) Delete(id int64) error {

	// check if the id is valid
	if id < 1 {
		return ErrRecordNotFound
	}
	// the SQL query to be executed against the database table
	query := `
        DELETE FROM books
        WHERE id = $1
		`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// ExecContext does not return any rows unlike QueryRowContext.
	// It only returns  information about the the query execution
	// such as how many rows were affected
	result, err := c.DB.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	// Probably a wrong id was provided or the client is trying to
	// delete an already deleted comment
	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	return nil

}

func (c BookModel) GetAll(filters Filters) ([]*Book, Metadata, error) {

	// the SQL query to be executed against the database table
	query := fmt.Sprintf(`
	SELECT COUNT(*) OVER(), id, title, authors, isbn, publication_date, genre, description, average_rating , version
	FROM books
	ORDER BY %s %s, id ASC
	LIMIT $1 OFFSET $2
	`, filters.sortColumn(), filters.sortDirection())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := c.DB.QueryContext(ctx, query, filters.limit(), filters.offset())

	if err != nil {
		return nil, Metadata{}, err
	}

	// clean up the memory that was used
	defer rows.Close()
	totalRecords := 0
	// we will store the address of each comment in our slice
	books := []*Book{}

	// process each row that is in rows

	for rows.Next() {
		var book Book
		err := rows.Scan(&totalRecords,
			&book.ID,
			&book.Title,
			&book.Authors,
			&book.ISBN,
			&book.PublicationDate,
			&book.Genre,
			&book.Description,
			&book.AverageRating,
			&book.Version,
		)
		if err != nil {
			return nil, Metadata{}, err
		}
		// add the row to our slice
		books = append(books, &book)
	} // end of for loop

	// after we exit the loop we need to check if it generated any errors
	err = rows.Err()
	if err != nil {
		return nil, Metadata{}, err
	}

	metadata := calculateMetaData(totalRecords, filters.Page, filters.PageSize)

	return books, metadata, nil

}

func (c BookModel) Search(title string, author string, genre string, filters Filters) ([]*Book, Metadata, error) {

	// the SQL query to be executed against the database table
	query := fmt.Sprintf(`
	SELECT COUNT(*) OVER(), id, title, authors, isbn, publication_date, genre, description, average_rating, version
	FROM books
	WHERE (to_tsvector('simple', title) @@
		  plainto_tsquery('simple', $1) OR $1 = '') 
	AND (to_tsvector('simple', authors) @@ 
		 plainto_tsquery('simple', $2) OR $2 = '')
	AND (to_tsvector('simple', genre) @@ 
		 plainto_tsquery('simple', $3) OR $3 = '') 
	ORDER BY %s %s, id ASC 
	LIMIT $4 OFFSET $5`, filters.sortColumn(), filters.sortDirection())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := c.DB.QueryContext(ctx, query, title, author, genre, filters.limit(), filters.offset())

	if err != nil {
		return nil, Metadata{}, err
	}

	// clean up the memory that was used
	defer rows.Close()
	totalRecords := 0
	// we will store the address of each comment in our slice
	books := []*Book{}

	// process each row that is in rows

	for rows.Next() {
		var book Book
		err := rows.Scan(&totalRecords,
			&book.ID,
			&book.Title,
			&book.Authors,
			&book.ISBN,
			&book.PublicationDate,
			&book.Genre,
			&book.Description,
			&book.AverageRating,
			&book.Version,
		)
		if err != nil {
			return nil, Metadata{}, err
		}
		// add the row to our slice
		books = append(books, &book)
	} // end of for loop

	// after we exit the loop we need to check if it generated any errors
	err = rows.Err()
	if err != nil {
		return nil, Metadata{}, err
	}

	metadata := calculateMetaData(totalRecords, filters.Page, filters.PageSize)

	return books, metadata, nil

}

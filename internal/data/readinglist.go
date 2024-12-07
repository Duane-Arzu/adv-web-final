package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// each name begins with uppercase so that they are exportable/public

type ReadingList struct {
	ID          int64  `json:"id"`          // Maps to 'id' in SQL
	Name        string `json:"name"`        // Maps to 'name' in SQL
	Description string `json:"description"` // Maps to 'description' in SQL
	CreatedBy   int    `json:"created_by"`  // Maps to 'created_by' in SQL
	Version     int    `json:"version"`     // Maps to 'version' in SQL
}

type BooksInList struct {
	ReadingListID int64  `json:"readinglist_id"`
	BookID        int64  `json:"book_id"`
	Status        string `json:"status"`
	Version       int16  `json:"version"`
}

type ReadingListModel struct {
	DB *sql.DB
}

func ValidateReadingList(v *validator.Validator, list *ReadingList) {
	// Validate Name
	v.Check(strings.TrimSpace(list.Name) != "", "name", "must be provided")
	v.Check(len(list.Name) <= 100, "name", "must not be more than 100 characters long")

	// Validate Description
	v.Check(strings.TrimSpace(list.Description) != "", "description", "must be provided")
	v.Check(len(list.Description) <= 200, "description", "must not be more than 200 characters long")

	// Validate CreatedBy (Foreign Key)
	v.Check(list.CreatedBy > 0, "created_by", "must be a valid user ID")
}

// validate if status for book being added to reading list is correct
func ValidateReadingStatus(v *validator.Validator, readingStatus string) {
	v.Check(readingStatus != "", "status", "must be provided")
	v.Check(readingStatus == "currently reading" || readingStatus == "completed",
		"status",
		"status must be of values 'completed' or 'currently reading'")
}

func (c ReadingListModel) Insert(list *ReadingList) error {
	// Create a context with a 3-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Check if the CreatedBy user exists
	var createdByExists bool
	err := c.DB.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)", list.CreatedBy).Scan(&createdByExists)
	if err != nil {
		return fmt.Errorf("error checking created_by user: %w", err)
	}
	if !createdByExists {
		return fmt.Errorf("invalid created_by ID: %d does not exist", list.CreatedBy)
	}

	query := `
		INSERT INTO readinglists (name, description, created_by) 
		VALUES ($1, $2, $3) 
		RETURNING id, version;
			 `

	args := []any{list.Name, list.Description, list.CreatedBy}

	err = c.DB.QueryRowContext(ctx, query, args...).Scan(&list.ID, &list.Version)
	if err != nil {
		return fmt.Errorf("error inserting reading list: %w", err)
	}

	return nil
}

// Get a specific Comment from the comments table
func (c ReadingListModel) Get(id int64) (*ReadingList, error) {
	// check if the id is valid
	if id < 1 {
		return nil, ErrRecordNotFound
	}
	// the SQL query to be executed against the database table
	query := `
		 SELECT  id, name, description, created_by, books, status, version
		 FROM readinglists
		 WHERE id = $1
	   `
	// declare a variable of type Comment to store the returned comment
	var list ReadingList

	// Set a 3-second context/timer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := c.DB.QueryRowContext(ctx, query, id).Scan(
		&list.ID,
		&list.Name,
		&list.Description,
		&list.CreatedBy,
		&list.Version,
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
	return &list, nil
}

func (c ReadingListModel) Update(list *ReadingList) error {
	// The SQL query to be executed against the database table
	// Every time we make an update, we increment the version number
	query := `
			UPDATE readinglists
			SET  name = $1, description = $2, created_by = $3, version = version + 1
			WHERE id = $4
			RETURNING version
			`

	args := []any{list.Name, list.Description, list.CreatedBy, list.ID}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.DB.QueryRowContext(ctx, query, args...).Scan(&list.Version)

}

func (c ReadingListModel) Delete(id int64) error {

	// check if the id is valid
	if id < 1 {
		return ErrRecordNotFound
	}
	// the SQL query to be executed against the database table
	query := `
        DELETE FROM readinglists
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

func (c ReadingListModel) GetAll(name string, filters Filters) ([]*ReadingList, Metadata, error) {

	// the SQL query to be executed against the database table
	query := fmt.Sprintf(`
	SELECT COUNT(*) OVER(), id, name, description, created_by, books, status, version
	FROM readinglists
	WHERE (to_tsvector('simple', name) @@
		  plainto_tsquery('simple', $1) OR $1 = '')
	AND (to_tsvector('simple', status) @@
		 plainto_tsquery('simple', $2) OR $2 = '')
	ORDER BY %s %s, id ASC
	LIMIT $3 OFFSET $4`, filters.sortColumn(), filters.sortDirection())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := c.DB.QueryContext(ctx, query, name, filters.limit(), filters.offset())
	if err != nil {
		return nil, Metadata{}, err
	}
	defer rows.Close()

	totalRecords := 0
	lists := []*ReadingList{}

	for rows.Next() {
		var list ReadingList
		// Scan the values, including the pointer for 'books'
		err := rows.Scan(&totalRecords,
			&list.ID,
			&list.Name,
			&list.Description,
			&list.CreatedBy,
			&list.Version,
		)
		if err != nil {
			return nil, Metadata{}, err
		}
		lists = append(lists, &list)
	}

	// Check for errors after the loop
	err = rows.Err()
	if err != nil {
		return nil, Metadata{}, err
	}

	metadata := calculateMetaData(totalRecords, filters.Page, filters.PageSize)
	return lists, metadata, nil
}

func (c *ReadingListModel) AddBookToList(book *BooksInList) error {

	query := `
	INSERT INTO readinglist_books (readinglist_id, book_id, status) 
	VALUES ($1, $2, $3) 
	RETURNING readinglist_id, version;
`
	args := []any{book.ReadingListID, book.BookID, book.Status}

	// Create a context with a 3-second timeout. No database
	// operation should take more than 3 seconds or we will quit it
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// execute the query against the comments database table. We ask for the the
	// id, created_at, and version to be sent back to us which we will use
	// to update the Comment struct later on
	return c.DB.QueryRowContext(ctx, query, args...).Scan(
		&book.ReadingListID,
		&book.Version)
}

func (c *ReadingListModel) RemoveBookFromList(listID, bookID int) error {

	query := `
	DELETE FROM readinglist_books
	WHERE readinglist_id = $1 AND book_id = $2
	`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	//excecute the query
	result, err := c.DB.ExecContext(ctx, query, listID, bookID)
	if err != nil {
		return err
	}

	//check if any rows affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound //no rows affected
	}
	return nil
}

func (b *ReadingListModel) ReadingListExist(id int64) error {

	if id < 1 {
		return ErrRecordNotFound
	}

	query := `
	SELECT id 
	FROM readinglists
	WHERE id = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var ID int64

	return b.DB.QueryRowContext(ctx, query, id).Scan(&ID)
}

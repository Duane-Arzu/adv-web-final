// internal/data/products.go
package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// Product represents the data structure for a product entity in the application,
// holding information about the product's identification, details, and metadata.
type Product struct {
	ProductID   int64     `json:"product_id"`  // Unique identifier for each product.
	Name        string    `json:"name"`        // Product name.
	Description string    `json:"description"` // Brief description of the product.
	Category    string    `json:"category"`    // Category the product belongs to.
	ImageURL    string    `json:"image_url"`   // URL link to the product image.
	Price       string    `json:"price"`       // Price of the product.
	AvgRating   float32   `json:"avg_rating"`  // Average rating from reviews, if available.
	CreatedAt   time.Time `json:"created_at"`  // Timestamp for when the product was created (not exposed in JSON).
	Version     int32     `json:"version"`     // Version for optimistic locking during updates.
}

// ProductModel provides methods for interacting with the products database table.
type ProductModel struct {
	DB *sql.DB // Database connection pool.
}

// ValidateProduct checks if the fields in the Product struct adhere to specified validation rules.
func ValidateProduct(v *validator.Validator, product *Product) {
	v.Check(product.Name != "", "name", "must be provided")                                              // Ensure product name is provided.
	v.Check(len(product.Name) <= 100, "name", "must not be more than 100 characters long")               // Name should not exceed 100 chars.
	v.Check(product.Description != "", "description", "must be provided")                                // Ensure description is present.
	v.Check(len(product.Description) <= 500, "description", "must not be more than 500 characters long") // Max length for description is 500 chars.
	v.Check(product.Category != "", "category", "must be provided")                                      // Category must be provided.
	v.Check(product.ImageURL != "", "image_url", "must be provided")                                     // Ensure an image URL is given.
	v.Check(len(product.ImageURL) <= 255, "image_url", "must not be more than 255 characters long")      // Limit image URL length.
	v.Check(len(product.Price) <= 10, "price", "must not be more than 10 characters long")               // Limit price field length.
	// v.Check(product.AverageRating >= 0 && product.AverageRating <= 5, "avg_rating", "must be between 0 and 5") // Ensure rating is within valid range.
}

// InsertProduct inserts a new product into the database, returning the product's unique ID, creation time, and version.
func (p ProductModel) InsertProduct(product *Product) error {
	query := `
		INSERT INTO products (name, description, category, image_url, price)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING product_id, created_at, version
	`
	args := []any{product.Name, product.Description, product.Category, product.ImageURL, product.Price}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return p.DB.QueryRowContext(ctx, query, args...).Scan(
		&product.ProductID,
		&product.CreatedAt,
		&product.Version,
	)
}

// GetProduct retrieves a product by its ID from the database, returning an error if not found.
func (p ProductModel) GetProduct(id int64) (*Product, error) {
	if id < 1 {
		return nil, ErrRecordNotFound // Return an error for invalid ID.
	}

	query := `
		SELECT product_id, name, description, category, image_url, price, avg_rating, created_at, version
		FROM products
		WHERE product_id = $1
	`

	var product Product
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := p.DB.QueryRowContext(ctx, query, id).Scan(
		&product.ProductID,
		&product.Name,
		&product.Description,
		&product.Category,
		&product.ImageURL,
		&product.Price,
		&product.AvgRating,
		&product.CreatedAt,
		&product.Version,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRecordNotFound // Return specific error if no rows are found.
		}
		return nil, err
	}

	return &product, nil
}

// UpdateProduct updates an existing product in the database, incrementing its version for concurrency control.
func (p ProductModel) UpdateProduct(product *Product) error {
	query := `
		UPDATE products
		SET name = $1, description = $2, category = $3, image_url = $4, price = $5, avg_rating = $6, version = version + 1
		WHERE product_id = $7
		RETURNING version
	`

	// Removed `product.UpdatedAt` from the args slice
	args := []any{product.Name, product.Description, product.Category, product.ImageURL, product.Price, product.AvgRating, product.ProductID}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return p.DB.QueryRowContext(ctx, query, args...).Scan(&product.Version)
}

// DeleteProduct deletes a product by its ID from the database and checks that a row was deleted.
func (p ProductModel) DeleteProduct(id int64) error {
	if id < 1 {
		return ErrRecordNotFound // Return an error if the ID is invalid.
	}

	query := `
		DELETE FROM products
		WHERE product_id = $1
	`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result, err := p.DB.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound // Return an error if no rows were deleted.
	}

	return nil
}

// GetAllProducts retrieves all products from the database, with support for name/category filtering
// and pagination controlled by the provided Filters struct.
func (p ProductModel) GetAllProducts(name string, category string, filters Filters) ([]*Product, Metadata, error) {
	query := fmt.Sprintf(`
		SELECT COUNT(*) OVER(), product_id, name, description, category, image_url, price, avg_rating, created_at, version
		FROM products
		WHERE (to_tsvector('simple', name) @@ plainto_tsquery('simple', $1) OR $1 = '') 
		AND (to_tsvector('simple', category) @@ plainto_tsquery('simple', $2) OR $2 = '') 
		ORDER BY %s %s, product_id ASC 
		LIMIT $3 OFFSET $4`, filters.sortColumn(), filters.sortDirection())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := p.DB.QueryContext(ctx, query, name, category, filters.limit(), filters.offset())
	if err != nil {
		return nil, Metadata{}, err
	}

	defer rows.Close()
	totalRecords := 0
	products := []*Product{}

	for rows.Next() {
		var product Product
		err := rows.Scan(
			&totalRecords,
			&product.ProductID,
			&product.Name,
			&product.Description,
			&product.Category,
			&product.ImageURL,
			&product.Price,
			&product.AvgRating,
			&product.CreatedAt,
			&product.Version,
		)
		if err != nil {
			return nil, Metadata{}, err
		}
		products = append(products, &product)
	}

	err = rows.Err()
	if err != nil {
		return nil, Metadata{}, err
	}

	// Calculate pagination metadata based on total records, current page, and page size.
	metadata := calculateMetaData(totalRecords, filters.Page, filters.PageSize)
	return products, metadata, nil
}

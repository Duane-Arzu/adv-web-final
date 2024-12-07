-- Creates the table for books
CREATE TABLE books (
    id bigserial PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    authors TEXT, 
    isbn VARCHAR(20) NOT NULL,
    publication_date TEXT,
    genre VARCHAR(100),
    description TEXT,
    average_rating DECIMAL(3, 2) DEFAULT 0.00, -- Average rating from reviews
    version integer NOT NULL DEFAULT 1
);
-- Create users table to store user data
CREATE TABLE IF NOT EXISTS users (
    id bigserial PRIMARY KEY,                -- Unique identifier for each user
    created_at timestamp(0) WITH TIME ZONE NOT NULL DEFAULT NOW(), -- Timestamp of user creation
    username text NOT NULL,                  -- User's chosen username
    email citext UNIQUE NOT NULL,            -- User's unique email address
    password_hash bytea NOT NULL,            -- Hashed password for security
    activated bool NOT NULL,                 -- Indicates if the user is activated
    version integer NOT NULL DEFAULT 1       -- Tracks the record version for updates
);

-- Create bookreviews table to store user reviews for books
CREATE TABLE IF NOT EXISTS bookreviews (
    id bigserial PRIMARY KEY,                -- Unique identifier for each review
    book_id INT DEFAULT 0 REFERENCES books(id) ON DELETE CASCADE, -- Associated book
    user_id INT REFERENCES users(id) ON DELETE CASCADE,           -- Reviewer
    rating FLOAT CHECK (rating BETWEEN 1 AND 5), -- Rating value (1-5)
    review TEXT,                              -- Review content
    review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Date of the review
    version integer NOT NULL DEFAULT 1       -- Tracks record version for updates
);

-- Create readinglists table for user-generated lists
CREATE TABLE IF NOT EXISTS readinglists (
    id bigserial PRIMARY KEY,                -- Unique identifier for each reading list
    name VARCHAR(255),                       -- Name of the reading list
    description TEXT,                        -- Description of the reading list
    created_by INT REFERENCES users(id) ON DELETE SET NULL, -- Creator of the list
    version integer NOT NULL DEFAULT 1       -- Tracks record version for updates
);

-- Create readinglist_books table to associate books with reading lists
CREATE TABLE IF NOT EXISTS readinglist_books (
    readinglist_id INT REFERENCES readinglists(id) ON DELETE CASCADE, -- Associated reading list
    book_id INT REFERENCES books(id) ON DELETE CASCADE,               -- Associated book
    status VARCHAR(50) CHECK (status IN ('currently reading', 'completed')), -- Reading status
    version integer NOT NULL DEFAULT 1,      -- Tracks record version for updates
    PRIMARY KEY (readinglist_id, book_id)    -- Ensures unique entries
);

-- Function to update average book rating based on reviews
CREATE OR REPLACE FUNCTION automatic_average_rating()
RETURNS TRIGGER AS $$
BEGIN
    -- Calculate and update the average rating for a book
    UPDATE books
    SET average_rating = (
        SELECT ROUND(CAST(AVG(rating) AS NUMERIC), 2)
        FROM bookreviews
        WHERE bookreviews.book_id = NEW.book_id
    )
    WHERE id = NEW.book_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to recalculate book rating on review changes
CREATE OR REPLACE TRIGGER update_book_rating
AFTER INSERT OR UPDATE OR DELETE ON bookreviews
FOR EACH ROW
EXECUTE FUNCTION automatic_average_rating();

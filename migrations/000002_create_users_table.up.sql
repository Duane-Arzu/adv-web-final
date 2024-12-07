-- Creates the table for users
CREATE TABLE IF NOT EXISTS users (
    id bigserial PRIMARY KEY,
    created_at timestamp(0) WITH TIME ZONE NOT NULL DEFAULT NOW(),
    username text NOT NULL,
    email citext UNIQUE NOT NULL,
    password_hash bytea NOT NULL,
    activated bool NOT NULL,
    version integer NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS bookreviews (
    id bigserial PRIMARY KEY,
    book_id INT DEFAULT 0 REFERENCES books(id) ON DELETE CASCADE,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,  
    rating FLOAT CHECK (rating BETWEEN 1 AND 5),
    review TEXT,
    review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    version integer NOT NULL DEFAULT 1
);

-- Create the readinglists table if it does not exist
CREATE TABLE IF NOT EXISTS readinglists (
    id bigserial PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    created_by INT REFERENCES users(id) ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS readinglist_books (
    readinglist_id INT REFERENCES readinglists(id) ON DELETE CASCADE,
    book_id INT REFERENCES books(id) ON DELETE CASCADE,
    status VARCHAR(50) CHECK (status IN ('currently reading', 'completed')),
    version integer NOT NULL DEFAULT 1,
    PRIMARY KEY (readinglist_id, book_id)
);


-- Function to calculate and update the average rating
CREATE OR REPLACE FUNCTION automatic_average_rating()
RETURNS TRIGGER AS $$
BEGIN
    -- Update the average rating of the book associated with the new review
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

-- Trigger that executes automatic_average_rating() when a review is added, updated, or deleted
CREATE OR REPLACE TRIGGER update_book_rating
AFTER INSERT OR UPDATE OR DELETE ON bookreviews
FOR EACH ROW
EXECUTE FUNCTION automatic_average_rating();
package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	// import the data package which contains the definition for Comment
	"github.com/Duane-Arzu/test3.git/internal/data"
	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// Struct to hold incoming review data
var incomingReviewData struct {
	Rating     *int64  `json:"rating"` // integer with a constraint (1-5)
	ReviewText *string `json:"review"` // non-null text field
}

// Updated createReviewHandler with product existence check
func (a *applicationDependencies) createReviewHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the book_id from the URL path
	bookID, err := a.readIDParam(r, "bid")
	if err != nil {
		a.badRequestResponse(w, r, errors.New("invalid or missing book_id in URL"))
		return
	}

	// Create a local instance of incomingReviewData
	var incomingReviewData struct {
		UserID     *int64  `json:"user_id"`
		Rating     *int64  `json:"rating"` // FLOAT with a constraint (1-5)
		ReviewText *string `json:"review"` // Non-null text field
	}

	// Decode the incoming JSON into the struct
	err = a.readJSON(w, r, &incomingReviewData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Check if required fields are provided
	if incomingReviewData.UserID == nil {
		a.badRequestResponse(w, r, errors.New("user_id is required"))
		return
	}
	if incomingReviewData.Rating == nil {
		a.badRequestResponse(w, r, errors.New("rating is required"))
		return
	}
	if *incomingReviewData.Rating < 1 || *incomingReviewData.Rating > 5 {
		a.badRequestResponse(w, r, errors.New("rating must be between 1 and 5"))
		return
	}
	if incomingReviewData.ReviewText == nil || len(strings.TrimSpace(*incomingReviewData.ReviewText)) == 0 {
		a.badRequestResponse(w, r, errors.New("review_text is required and cannot be empty"))
		return
	}

	// Check if the book exists in the database
	exists, err := a.bookModel.BookExists(bookID)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	if !exists {
		a.BIDnotFound(w, r, bookID) // Respond with a 404 if book is not found
		return
	}

	// Create the review object based on the incoming data
	review := &data.Review{
		BookID:     bookID,
		UserID:     *incomingReviewData.UserID,
		Rating:     *incomingReviewData.Rating,
		ReviewText: *incomingReviewData.ReviewText,
		ReviewDate: time.Now(),
	}

	// Initialize a Validator instance
	v := validator.New()

	// Validate the review object
	data.ValidateReview(v, review)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Insert the review into the database
	err = a.reviewModel.InsertReview(review)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Set a Location header. The path to the newly created review
	headers := make(http.Header)
	headers.Set("Location", fmt.Sprintf("/api/v1/books/%d/reviews/%d", review.BookID, review.ReviewID))

	data := envelope{
		"review": review,
	}
	err = a.writeJSON(w, http.StatusCreated, data, headers)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) displayReviewHandler(w http.ResponseWriter, r *http.Request) {
	// Get the "bid" (book ID) from the URL for potential use or validation
	bid, err := a.readIDParam(r, "bid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Check if the book exists in the database
	exists, err := a.bookModel.BookExists(bid)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	if !exists {
		a.BIDnotFound(w, r, bid) // Respond with a 404 if book is not found
		return
	}

	// Get the "rid" (review ID) from the URL
	rid, err := a.readIDParam(r, "rid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Call GetReview() to retrieve the review with the specified id
	review, err := a.reviewModel.GetReview(rid)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	// Display the review
	data := envelope{
		"Review": review,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) bookReviewsHandler(w http.ResponseWriter, r *http.Request) {
	// Get the "id" (book ID) from the URL
	bookID, err := a.readIDParam(r, "bid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Check if the book exists in the database
	exists, err := a.bookModel.BookExists(bookID)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	if !exists {
		a.BIDnotFound(w, r, bookID) // Respond with a 404 if the book is not found
		return
	}

	// Retrieve all reviews for the specified book
	reviews, err := a.reviewModel.GetAllBookReviews(bookID)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Return the reviews in JSON format
	data := envelope{
		"reviews": reviews,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) updateReviewHandler(w http.ResponseWriter, r *http.Request) {
	// Read the review ID from the URL parameter
	id, err := a.readIDParam(r, "rid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Retrieve the review from the database
	review, err := a.reviewModel.GetReview(id)
	if err != nil {
		if errors.Is(err, data.ErrRecordNotFound) {
			a.notFoundResponse(w, r)
		} else {
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	// // Define a struct to hold incoming JSON data
	// var incomingReviewData struct {
	// 	Rating     *int64  `json:"rating"`      // integer with a constraint (1-5)
	// 	ReviewText *string `json:"review_text"` // non-null text field
	// }

	// Decode the incoming JSON into the struct
	err = a.readJSON(w, r, &incomingReviewData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	if incomingReviewData.Rating != nil {
		review.Rating = *incomingReviewData.Rating
	}
	if incomingReviewData.ReviewText != nil {
		review.ReviewText = *incomingReviewData.ReviewText
	}

	// Validate the updated review
	v := validator.New()
	data.ValidateReview(v, review) // Assuming ValidateReview is the correct validation function for reviews
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Update the review in the database
	err = a.reviewModel.UpdateReview(review)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Send the updated review as a JSON response
	data := envelope{
		"review": review,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

func (a *applicationDependencies) deleteReviewHandler(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r, "rid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	err = a.reviewModel.DeleteReview(id)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.RIDnotFound(w, r, id) // Pass the ID to the custom message handler
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	data := envelope{
		"message": "Review successfully deleted",
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

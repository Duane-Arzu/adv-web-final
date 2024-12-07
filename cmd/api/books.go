package main

import (
	"errors"
	"fmt"
	"net/http"

	// import the data package which contains the definition for Comment
	"github.com/Duane-Arzu/test3.git/internal/data"
	"github.com/Duane-Arzu/test3.git/internal/validator"
)

var incomingData struct {
	Title           *string `json:"title"`
	Authors         *string `json:"authors"`
	ISBN            *string `json:"isbn"`
	PublicationDate *string `json:"publication_date"` // Use string to parse and validate date later
	Genre           *string `json:"genre"`
	Description     *string `json:"description"`
}

func (a *applicationDependencies) createBookHandler(w http.ResponseWriter, r *http.Request) {
	// create a struct to hold a comment
	// we use struct tags to make the names display in lowercase
	var incomingData struct {
		Title           string `json:"title"`
		Authors         string `json:"authors"`
		ISBN            string `json:"isbn"`
		PublicationDate string `json:"publication_date"` // Use string to parse and validate date later
		Genre           string `json:"genre"`
		Description     string `json:"description"`
	}
	// perform the decoding
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	book := &data.Book{
		Title:           incomingData.Title,
		Authors:         incomingData.Authors,
		ISBN:            incomingData.ISBN,
		PublicationDate: incomingData.PublicationDate,
		Genre:           incomingData.Genre,
		Description:     incomingData.Description,
	}
	// Initialize a Validator instance
	v := validator.New()

	data.ValidateBook(v, book)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors) // implemented later
		return
	}
	err = a.bookModel.Insert(book)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Set a Location header. The path to the newly created comment
	headers := make(http.Header)
	headers.Set("Location", fmt.Sprintf("/api/v1/books/%d", book.ID))

	data := envelope{
		"Book": book,
	}
	err = a.writeJSON(w, http.StatusCreated, data, headers)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

}

func (a *applicationDependencies) displayBookHandler(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r, "bid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	book, err := a.bookModel.Get(id)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	// display the comment
	data := envelope{
		"Book": book,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

}

func (a *applicationDependencies) updateBookHandler(w http.ResponseWriter, r *http.Request) {
	// Get the ID from the URL
	id, err := a.readIDParam(r, "bid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Retrieve the comment from the database
	book, err := a.bookModel.Get(id)
	if err != nil {
		if errors.Is(err, data.ErrRecordNotFound) {
			a.notFoundResponse(w, r)
		} else {
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	// Decode the incoming JSON
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Update the comment fields based on the incoming data
	if incomingData.Title != nil {
		book.Title = *incomingData.Title
	}
	if incomingData.Authors != nil {
		book.Authors = *incomingData.Authors
	}
	if incomingData.ISBN != nil {
		book.ISBN = *incomingData.ISBN
	}
	if incomingData.PublicationDate != nil {
		book.PublicationDate = *incomingData.PublicationDate
	}
	if incomingData.Genre != nil {
		book.Genre = *incomingData.Genre
	}
	if incomingData.Description != nil {
		book.Description = *incomingData.Description
	}

	// Validate the updated comment
	v := validator.New()
	data.ValidateBook(v, book)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Perform the update in the database
	err = a.bookModel.Update(book)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Respond with the updated comment
	data := envelope{
		"Book": book,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) deleteBookHandler(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r, "bid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	err = a.bookModel.Delete(id)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.BIDnotFound(w, r, id) // Pass the ID to the custom message handler
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	data := envelope{
		"message": "Book successfully deleted",
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

func (a *applicationDependencies) listBooksHandler(w http.ResponseWriter, r *http.Request) {
	//to hold query parameters
	var queryParameterData struct {
		data.Filters
	}

	//get query parameters from url
	queryParameter := r.URL.Query()

	v := validator.New()

	queryParameterData.Filters.Page = a.getSingleIntegerParameter(queryParameter, "page", 1, v)
	queryParameterData.Filters.PageSize = a.getSingleIntegerParameter(queryParameter, "page_size", 10, v)
	queryParameterData.Filters.Sort = a.getSingleQueryParameter(queryParameter, "sort", "id")
	queryParameterData.Filters.SortSafeList = []string{"id", "title", "author", "genre", "-id", "-title", "-author", "-genre"}

	data.ValidateFilters(v, queryParameterData.Filters)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	books, metadata, err := a.bookModel.GetAll(queryParameterData.Filters)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
			return
		default:
			a.serverErrorResponse(w, r, err)
			return
		}
	}
	data := envelope{
		"books":     books,
		"@metadata": metadata,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) searchBookHandler(w http.ResponseWriter, r *http.Request) {
	//to hold query parameters
	var queryParameterData struct {
		Title  string
		Author string
		Genre  string
		data.Filters
	}

	//get query parameters from url
	queryParameter := r.URL.Query()

	//load the query parameters into the created struct
	queryParameterData.Title = a.getSingleQueryParameter(queryParameter, "title", "")
	queryParameterData.Author = a.getSingleQueryParameter(queryParameter, "author", "")
	queryParameterData.Genre = a.getSingleQueryParameter(queryParameter, "genre", "")
	v := validator.New()

	queryParameterData.Filters.Page = a.getSingleIntegerParameter(queryParameter, "page", 1, v)
	queryParameterData.Filters.PageSize = a.getSingleIntegerParameter(queryParameter, "page_size", 10, v)
	queryParameterData.Filters.Sort = a.getSingleQueryParameter(queryParameter, "sort", "id")
	queryParameterData.Filters.SortSafeList = []string{"id", "title", "author", "genre", "-id", "-title", "-author", "-genre"}

	data.ValidateFilters(v, queryParameterData.Filters)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	books, metadata, err := a.bookModel.Search(queryParameterData.Title, queryParameterData.Author, queryParameterData.Genre, queryParameterData.Filters)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
			return
		default:
			a.serverErrorResponse(w, r, err)
			return
		}
	}
	data := envelope{
		"books":     books,
		"@metadata": metadata,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

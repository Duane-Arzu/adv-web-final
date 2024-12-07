package main

import (
	"errors"
	"fmt"
	"net/http"

	// import the data package which contains the definition for Comment
	"github.com/Duane-Arzu/test3.git/internal/data"
	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// Create a local struct to hold incoming data
var incomingListData struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	CreatedBy   *int    `json:"created_by"`
}

func (a *applicationDependencies) createReadingListHandler(w http.ResponseWriter, r *http.Request) {
	// Create a struct to hold incoming data with the correct field names and JSON tags
	var incomingListData struct {
		Name        string `json:"name"`        // Maps to 'name' in JSON
		Description string `json:"description"` // Maps to 'description' in JSON
		CreatedBy   int    `json:"created_by"`  // Maps to 'created_by' in JSON
	}

	// Perform the decoding of the incoming JSON
	err := a.readJSON(w, r, &incomingListData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	list := &data.ReadingList{
		Name:        incomingListData.Name,
		Description: incomingListData.Description,
		CreatedBy:   incomingListData.CreatedBy,
	}

	// Initialize a Validator instance
	v := validator.New()
	data.ValidateReadingList(v, list)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Insert the reading list into the database
	err = a.readingListModel.Insert(list)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Set a Location header. The path to the newly created reading list
	headers := make(http.Header)
	headers.Set("Location", fmt.Sprintf("/api/v1/lists/%d", list.ID))

	data := envelope{
		"Reading List": list,
	}
	err = a.writeJSON(w, http.StatusCreated, data, headers)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) updateReadingListHandler(w http.ResponseWriter, r *http.Request) {
	// Get the ID from the URL
	id, err := a.readIDParam(r, "lid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Retrieve the reading list from the database
	list, err := a.readingListModel.Get(id)
	if err != nil {
		if errors.Is(err, data.ErrRecordNotFound) {
			a.notFoundResponse(w, r)
		} else {
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	err = a.readJSON(w, r, &incomingListData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Update the fields if new values are provided
	if incomingListData.Name != nil {
		list.Name = *incomingListData.Name
	}
	if incomingListData.Description != nil {
		list.Description = *incomingListData.Description
	}
	if incomingListData.CreatedBy != nil {
		list.CreatedBy = *incomingListData.CreatedBy
	}

	// Validate the updated reading list
	v := validator.New()
	data.ValidateReadingList(v, list)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Perform the update in the database
	err = a.readingListModel.Update(list)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Send the updated reading list as a response
	data := envelope{
		"Reading List": list,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) displayReadingListHandler(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r, "lid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	list, err := a.readingListModel.Get(id)
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
		"Reading List": list,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

}

func (a *applicationDependencies) deleteReadingListHandler(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r, "lid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	err = a.readingListModel.Delete(id)
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
		"message": "Readling List successfully deleted",
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

func (a *applicationDependencies) ReadinglistHandler(w http.ResponseWriter, r *http.Request) {
	// Create a struct to hold the query parameters
	// Later on we will add fields for pagination and sorting (filters)
	var queryParametersData struct {
		Name string
		data.Filters
	}
	// get the query parameters from the URL
	queryParameters := r.URL.Query()
	// Load the query parameters into our struct
	queryParametersData.Name = a.getSingleQueryParameter(
		queryParameters,
		"name",
		"")

	v := validator.New()
	queryParametersData.Filters.Page = a.getSingleIntegerParameter(
		queryParameters, "page", 1, v)
	queryParametersData.Filters.PageSize = a.getSingleIntegerParameter(
		queryParameters, "page_size", 10, v)

	queryParametersData.Filters.Sort = a.getSingleQueryParameter(
		queryParameters, "sort", "id")

	queryParametersData.Filters.SortSafeList = []string{"id", "name", "status",
		"-id", "-name", "-status"}

	// Check if our filters are valid
	data.ValidateFilters(v, queryParametersData.Filters)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	lists, metadata, err := a.readingListModel.GetAll(
		queryParametersData.Name,
		queryParametersData.Filters,
	)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	data := envelope{
		"Reading Lists": lists,
		"@metadata":     metadata,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

func (a *applicationDependencies) addReadingListBookHandler(w http.ResponseWriter, r *http.Request) {
	//create a struct to hold a list
	var incomingData struct {
		BookID int64  `json:"book_id"`
		Status string `json:"status"`
	}

	//get list id parameter
	id, err := a.readIDParam(r, "lid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	//decode
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	bookInList := &data.BooksInList{
		ReadingListID: id,
		BookID:        incomingData.BookID,
		Status:        incomingData.Status,
	}

	//validate status
	v := validator.New()
	data.ValidateReadingStatus(v, incomingData.Status)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	//check if reading list exist
	err = a.readingListModel.ReadingListExist(id)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Check if the book exists in the database
	exists, err := a.bookModel.BookExists(incomingData.BookID)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	if !exists {
		a.BIDnotFound(w, r, incomingData.BookID) // Respond with a 404 if the book is not found
		return
	}

	//procede to insert to DB
	err = a.readingListModel.AddBookToList(bookInList)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrDuplicateBookInList):
			v.AddError("book", data.ErrDuplicateBookInList.Error())
			a.failedValidationResponse(w, r, v.Errors)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	headers := make(http.Header)
	headers.Set("Location", fmt.Sprintf("/api/v1/lists/%d/books", incomingData.BookID))

	data := envelope{
		"Added_Book": bookInList,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) RemoveReadingListBookHandler(w http.ResponseWriter, r *http.Request) {
	//fetch the list book belongs to id
	list_id, err := a.readIDParam(r, "lid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	var incomingData struct {
		BookID int `json:"book_id"`
	}

	//get book it
	err = a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Check if the book exists in the database
	exists, err := a.bookModel.BookExists(int64(incomingData.BookID))
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	if !exists {
		a.BIDnotFound(w, r, int64(incomingData.BookID)) // Respond with a 404 if the book is not found
		return
	}

	//check if reading list exists
	err = a.readingListModel.ReadingListExist(list_id)
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	//procede to delete book from reading list
	err = a.readingListModel.RemoveBookFromList(incomingData.BookID, int(list_id))
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}
	//display the message
	data := envelope{
		"Message": "Book removed from  Reading List sucessfully",
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}

}

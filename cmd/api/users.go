// Filename: cmd/api/users.go
package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/data"
	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// Handler to register a new user
func (a *applicationDependencies) registerUserHandler(w http.ResponseWriter,
	r *http.Request) {
	// Read incoming JSON data and store it in a struct
	var incomingData struct {
		Username string `json:"username"` // New user's username
		Email    string `json:"email"`    // New user's email
		Password string `json:"password"` // New user's password
	}
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		// Respond with a "bad request" error if the JSON is invalid
		a.badRequestResponse(w, r, err)
		return
	}
	// Create a new user object with the received data
	user := &data.User{
		Username:  incomingData.Username,
		Email:     incomingData.Email,
		Activated: false,
	}
	// Hash the provided password
	err = user.Password.Set(incomingData.Password)
	if err != nil {
		// Respond with a "server error" if password hashing fails
		a.serverErrorResponse(w, r, err)
		return
	}
	// Validate the user's data
	v := validator.New()

	data.ValidateUser(v, user)
	// If validation errors exist, respond with a "failed validation" error
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Insert the user into the database
	err = a.userModel.Insert(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrDuplicateEmail):
			v.AddError("email", "a user with this email address already exists")
			a.failedValidationResponse(w, r, v.Errors)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}
	token, err := a.tokenModel.New(user.ID, 3*24*time.Hour, data.ScopeActivation)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	data := envelope{
		"user": user,
	}
	a.background(func() {
		data := map[string]any{
			"activationToken": token.Plaintext,
			"userID":          user.ID,
		}

		err = a.mailer.Send(user.Email, "user_welcome.tmpl", data)
		if err != nil {
			a.logger.Error(err.Error())
		}
	})

	// Respond with a "resource created" status and the new user data
	err = a.writeJSON(w, http.StatusCreated, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) activateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Read the activation token from the request body
	var incomingData struct {
		TokenPlaintext string `json:"token"`
	}
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}
	// Validate the data
	v := validator.New()
	data.ValidateTokenPlaintext(v, incomingData.TokenPlaintext)
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Find the user associated with the token
	user, err := a.userModel.GetForToken(data.ScopeActivation,
		incomingData.TokenPlaintext)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			v.AddError("token", "invalid or expired activation token")
			a.failedValidationResponse(w, r, v.Errors)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}
	// User provided the right token so activate them
	user.Activated = true
	err = a.userModel.Update(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrEditConflict):
			a.editConflictResponse(w, r)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}
	err = a.tokenModel.DeleteAllForUser(data.ScopeActivation, user.ID)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Send a response
	data := envelope{
		"user": user,
	}
	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
	}
}

func (a *applicationDependencies) listUserProfileHandler(w http.ResponseWriter, r *http.Request) {
	//get the id from the URL so that we can use it to query the comments table.
	//'uid' for userID
	id, err := a.readIDParam(r, "uid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	user, err := a.userModel.GetByID(id)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.notFoundResponse(w, r)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	//display the user information
	data := envelope{
		"user": user,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) getUserReviewsHandler(w http.ResponseWriter, r *http.Request) {
	// Get the id from the URL so that we can use it to query the comments table.
	//'uid' for userID
	id, err := a.readIDParam(r, "uid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Get the reviews for the user
	reviews, err := a.userModel.GetUserReviews(id)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Display the user information along with their reviews
	data := envelope{

		"User Reviews": reviews,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

func (a *applicationDependencies) getUserListsHandler(w http.ResponseWriter, r *http.Request) {
	id, err := a.readIDParam(r, "uid")
	if err != nil {
		a.notFoundResponse(w, r)
		return
	}

	// Get the reviews for the user
	lists, err := a.userModel.GetUserLists(id)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	// Display the user information along with their reviews
	data := envelope{

		"User Lists": lists,
	}

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

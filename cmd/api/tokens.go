// Filename: cmd/api/tokens.go
package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/Duane-Arzu/test3.git/internal/data"
	"github.com/Duane-Arzu/test3.git/internal/validator"
)

func (a *applicationDependencies) createAuthenticationTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Define a struct to hold the incoming JSON data
	var incomingData struct {
		Email    string `json:"email"`    // User's email
		Password string `json:"password"` // User's password
	}

	// Parse the JSON input into the struct
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		// Send a "bad request" response if the JSON is invalid
		a.badRequestResponse(w, r, err)
		return
	}

	// Initialize a new validator
	v := validator.New()

	// Validate the email and password fields
	data.ValidateEmail(v, incomingData.Email)                // Check if the email is valid
	data.ValidatePasswordPlaintext(v, incomingData.Password) // Check if the password meets criteria

	// If there are validation errors, send a "failed validation" response
	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}

	// Check if the email exists in the database
	user, err := a.userModel.GetByEmail(incomingData.Email)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound): // No user found for the given email
			a.invalidCredentialsResponse(w, r)
		default: // Some other server error occurred
			a.serverErrorResponse(w, r, err)
		}
		return
	}

	// Verify if the provided password matches the stored password
	match, err := user.Password.Matches(incomingData.Password)
	if err != nil {
		// Send a "server error" response if there's an issue with the password check
		a.serverErrorResponse(w, r, err)
		return
	}

	// If the password does not match, send an "invalid credentials" response
	if !match {
		a.invalidCredentialsResponse(w, r)
		return
	}

	// Create a new authentication token for the user
	token, err := a.tokenModel.New(user.ID, 24*time.Hour, data.ScopeAuthentication)
	if err != nil {
		// Send a "server error" response if token creation fails
		a.serverErrorResponse(w, r, err)
		return
	}

	// Wrap the token in an envelope to send as a JSON response
	data := envelope{
		"authentication_token": token,
	}

	// Send the token back to the client with a "Created" (201) status
	err = a.writeJSON(w, http.StatusCreated, data, nil)
	if err != nil {
		// Send a "server error" response if JSON writing fails
		a.serverErrorResponse(w, r, err)
	}
}

// Filename: cmd/api/tokens.go
package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/Duane-Arzu/adv-web-final.git/internal/data"
	"github.com/Duane-Arzu/adv-web-final.git/internal/validator"
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

func (a *applicationDependencies) passwordResetTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Get the passed-in email address from the request body
	var incomingData struct {
		Email string `json:"email"`
	}
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}

	// Fetch user by email address
	user, err := a.userModel.GetByEmail(incomingData.Email)
	if err != nil {
		// If no user is found, assume it's not registered; return 404 to avoid leaking information
		a.notFoundResponse(w, r)
		return
	}

	// Generate a password reset token
	token, err := a.tokenModel.New(user.ID, 30*time.Minute, data.ScopePasswordReset)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	data := envelope{
		"message": "an email will be sent to you containing the password reset instructions",
	}
	a.background(func() {
		emailData := map[string]any{
			"passwordResetToken": token.Plaintext, // Send the plaintext token in the email
			"userID":             user.ID,
		}

		err = a.mailer.Send(user.Email, "password_reset.tmpl", emailData)
		if err != nil {
			a.logger.Error("failed to send password reset email: " + err.Error())
		}
	})

	// Respond with a success message (don't send the token in the response)

	err = a.writeJSON(w, http.StatusOK, data, nil)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
}

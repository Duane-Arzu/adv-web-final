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
	var incomingData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := a.readJSON(w, r, &incomingData)
	if err != nil {
		a.badRequestResponse(w, r, err)
		return
	}
	v := validator.New()

	data.ValidateEmail(v, incomingData.Email)
	data.ValidatePasswordPlaintext(v, incomingData.Password)

	if !v.IsEmpty() {
		a.failedValidationResponse(w, r, v.Errors)
		return
	}
	// Is there an associated user for the provided email?
	user, err := a.userModel.GetByEmail(incomingData.Email)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			a.invalidCredentialsResponse(w, r)
		default:
			a.serverErrorResponse(w, r, err)
		}
		return
	}
	// The user is found. Does their password match?
	match, err := user.Password.Matches(incomingData.Password)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}
	// Wrong password
	// We will define invalidCredentialsResponse() later
	if !match {
		a.invalidCredentialsResponse(w, r)
		return
	}
	token, err := a.tokenModel.New(user.ID, 24*time.Hour, data.ScopeAuthentication)
	if err != nil {
		a.serverErrorResponse(w, r, err)
		return
	}

	data := envelope{
		"authentication_token": token,
	}

	// Return the bearer token
	err = a.writeJSON(w, http.StatusCreated, data, nil)
	if err != nil {
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

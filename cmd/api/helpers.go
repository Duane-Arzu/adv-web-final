package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Duane-Arzu/test3.git/internal/validator"

	"github.com/julienschmidt/httprouter"
)

type envelope map[string]any

func (a *applicationDependencies) writeJSON(w http.ResponseWriter, status int, data envelope, headers http.Header) error {
	jsResponse, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return err
	}
	jsResponse = append(jsResponse, '\n')

	for key, value := range headers {
		w.Header()[key] = value
	}

	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(status)
	_, err = w.Write(jsResponse)
	if err != nil {
		return err
	}

	return nil

}

func (a *applicationDependencies) readJSON(w http.ResponseWriter,
	r *http.Request,
	destination any) error {

	maxBytes := 256_000
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(destination)

	if err != nil {

		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError
		var invalidUnmarshalError *json.InvalidUnmarshalError
		var maxBytesError *http.MaxBytesError

		switch {
		case errors.As(err, &syntaxError):
			return fmt.Errorf("the body contains badly-formed JSON (at character %d)", syntaxError.Offset)
			// Decode can also send back an io error message
		case errors.Is(err, io.ErrUnexpectedEOF):
			return errors.New("the body contains badly-formed JSON")

		case errors.As(err, &unmarshalTypeError):
			if unmarshalTypeError.Field != "" {
				return fmt.Errorf("the body contains the incorrect JSON type for field %q", unmarshalTypeError.Field)
			}
			return fmt.Errorf("the body contains the incorrect  JSON type (at character %d)",
				unmarshalTypeError.Offset)
		case errors.Is(err, io.EOF):
			return errors.New("the body must not be empty")

		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(),
				"json: unknown field ")
			return fmt.Errorf("body contains unknown key %s", fieldName)

		case errors.As(err, &maxBytesError):
			return fmt.Errorf("the body must not be larger that %d bytes", maxBytesError.Limit)
		case errors.Is(err, io.EOF):
			return errors.New("the body must not be empty")

		case strings.HasPrefix(err.Error(), "json: unknown field "):
			fieldName := strings.TrimPrefix(err.Error(), "json: unknown field ")
			return fmt.Errorf("body contains unknown key %s", fieldName)

		case errors.As(err, &maxBytesError):
			return fmt.Errorf("the body must not be larger that %d bytes", maxBytesError.Limit)

		case errors.Is(err, io.EOF):
			return errors.New("the body must not be empty")

		case errors.As(err, &invalidUnmarshalError):
			panic(err)

		default:
			return err
		}
	}

	err = dec.Decode(&struct{}{})

	if !errors.Is(err, io.EOF) {
		return errors.New("body must only contain a single JSON value")
	}

	return nil
}

func (a *applicationDependencies) readIDParam(r *http.Request, sid string) (int64, error) {
	//get the url parameters
	params := httprouter.ParamsFromContext(r.Context())
	//convert id from string to int
	id, err := strconv.ParseInt(params.ByName(sid), 10, 64)
	if err != nil || id < 1 {
		return 0, errors.New("invalid ID parameter")
	}

	return id, nil
}

func (a *applicationDependencies) getSingleQueryParameter(queryParameters url.Values, key string, defaultValue string) string {

	result := queryParameters.Get(key)
	if result == "" {
		return defaultValue
	}
	return result
}

// func (a *applicationDependencies) getMultipleQueryParameters(queryParameters url.Values, key string, defaultValue []string) []string {

// 	result := queryParameters.Get(key)
// 	if result == "" {
// 		return defaultValue
// 	}
// 	return strings.Split(result, ",")
// }

func (a *applicationDependencies) getSingleIntegerParameter(queryParameters url.Values, key string, defaultValue int, v *validator.Validator) int {

	result := queryParameters.Get(key)
	if result == "" {
		return defaultValue
	}
	// try to convert to an integer
	intValue, err := strconv.Atoi(result)
	if err != nil {
		v.AddError(key, "must be an integer value")
		return defaultValue
	}

	return intValue
}
func (a *applicationDependencies) background(fn func()) {
	a.wg.Add(1) // Use a wait group to ensure all goroutines finish before we exit
	go func() {
		defer a.wg.Done() // signal goroutine is done
		defer func() {
			err := recover()
			if err != nil {
				a.logger.Error(fmt.Sprintf("%v", err))
			}
		}()
		fn() // Run the actual function
	}()
}

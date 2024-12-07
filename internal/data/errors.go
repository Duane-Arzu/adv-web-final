package data

import (
	"errors"
)

var ErrRecordNotFound = errors.New("record not found")

var ErrDuplicateEmail = errors.New("duplicate email")
var ErrEditConflict = errors.New("edit conflict")

var ErrDuplicateBookInList = errors.New("duplicate book in reading list")

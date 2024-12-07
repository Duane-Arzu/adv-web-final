// Filename: internal/data/filters.go
package data

import (
	"strings"

	"github.com/Duane-Arzu/test3.git/internal/validator"
)

// Filters holds pagination and sorting options.
type Filters struct {
	Page         int      // Current page number.
	PageSize     int      // Number of records per page.
	Sort         string   // Sorting field, e.g., "name" or "-date".
	SortSafeList []string // Allowed fields for sorting to prevent unsafe queries.
}

// Metadata provides pagination details for the client.
type Metadata struct {
	CurrentPage  int `json:"current_page,omitempty"`  // Active page number.
	PageSize     int `json:"page_size,omitempty"`     // Records per page.
	FirstPage    int `json:"first_page,omitempty"`    // First page (always 1).
	LastPage     int `json:"last_page,omitempty"`     // Total number of pages.
	TotalRecords int `json:"total_records,omitempty"` // Total number of records.
}

// ValidateFilters ensures pagination and sorting inputs are valid.
func ValidateFilters(v *validator.Validator, f Filters) {
	v.Check(f.Page > 0, "page", "must be greater than zero")                                   // Page must be positive.
	v.Check(f.Page <= 500, "page", "must not exceed 500")                                      // Limit maximum page number.
	v.Check(f.PageSize > 0, "page_size", "must be greater than zero")                          // Page size must be positive.
	v.Check(f.PageSize <= 100, "page_size", "must not exceed 100")                             // Limit maximum records per page.
	v.Check(validator.PermittedValue(f.Sort, f.SortSafeList...), "sort", "invalid sort value") // Ensure sort field is allowed.
}

// sortColumn returns the column to sort by after validating it.
func (f Filters) sortColumn() string {
	for _, safeValue := range f.SortSafeList {
		if f.Sort == safeValue {
			return strings.TrimPrefix(f.Sort, "-") // Strip "-" for ascending order.
		}
	}
	// Stop execution if the sort field is unsafe.
	panic("unsafe sort parameter: " + f.Sort)
}

// sortDirection returns the sorting order: "ASC" or "DESC".
func (f Filters) sortDirection() string {
	if strings.HasPrefix(f.Sort, "-") {
		return "DESC" // Use descending for "-" prefix.
	}
	return "ASC" // Default to ascending order.
}

// limit specifies the number of records per page.
func (f Filters) limit() int {
	return f.PageSize
}

// offset calculates how many records to skip for the current page.
func (f Filters) offset() int {
	return (f.Page - 1) * f.PageSize
}

// calculateMetaData generates metadata for the current pagination state.
func calculateMetaData(totalRecords int, currentPage int, pageSize int) Metadata {
	if totalRecords == 0 {
		return Metadata{} // Return empty metadata if no records.
	}

	return Metadata{
		CurrentPage:  currentPage,                              // Current active page.
		PageSize:     pageSize,                                 // Records per page.
		FirstPage:    1,                                        // First page is always 1.
		LastPage:     (totalRecords + pageSize - 1) / pageSize, // Calculate total pages.
		TotalRecords: totalRecords,                             // Total number of records available.
	}
}

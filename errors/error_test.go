package errors_test

import (
	"fmt"
	"testing"

	"github.com/macrat/lauth/errors"
)

func TestErrorString(t *testing.T) {
	tests := []struct {
		String string
		Error  *errors.Error
	}{
		{
			"invalid_request",
			&errors.Error{
				Reason: errors.InvalidRequest,
			},
		},
		{
			"server_error: this is description",
			&errors.Error{
				Reason:      errors.ServerError,
				Description: "this is description",
			},
		},
		{
			"invalid_client: this is error",
			&errors.Error{
				Reason: errors.InvalidClient,
				Err:    fmt.Errorf("this is error"),
			},
		},
		{
			"invalid_grant: desc: err",
			&errors.Error{
				Reason:      errors.InvalidGrant,
				Description: "desc",
				Err:         fmt.Errorf("err"),
			},
		},
	}

	for _, tt := range tests {
		got := tt.Error.Error()
		if got != tt.String {
			t.Errorf("expected %#v but got %#v", tt.String, got)
		}
	}
}

package stepauth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestNewProtocolErrorMapsStatus(t *testing.T) {
	tests := []struct {
		code Code
		want int
	}{
		{CodeApproverSetTooLarge, http.StatusBadRequest},
		{CodeDuplicateRequest, http.StatusConflict},
		{CodeInvalidCallbackURL, http.StatusBadRequest},
		{CodeInvalidSignature, http.StatusUnauthorized},
		{CodeMalformedRequest, http.StatusBadRequest},
		{CodeOperatorDepthExceeded, http.StatusBadRequest},
		{CodeRequestNotFound, http.StatusNotFound},
		{CodeTimestampOutOfRange, http.StatusBadRequest},
		{CodeUnknownApprover, http.StatusBadRequest},
		{CodeUnknownCategory, http.StatusBadRequest},
		{CodeUnknownSender, http.StatusUnauthorized},
		{CodeWrongRecipient, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			got := NewProtocolError(tt.code, "").HTTPStatus
			if got != tt.want {
				t.Errorf("NewProtocolError(%s).HTTPStatus = %d, want %d", tt.code, got, tt.want)
			}
		})
	}
}

func TestNewProtocolErrorUnknownCodeDefaultsTo400(t *testing.T) {
	got := NewProtocolError(Code("something_new"), "").HTTPStatus
	if got != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want %d", got, http.StatusBadRequest)
	}
}

func TestProtocolErrorMessage(t *testing.T) {
	e := NewProtocolError(CodeMalformedRequest, "missing requestId")
	if got := e.Error(); got == "" || got == string(CodeMalformedRequest) {
		t.Errorf("Error() = %q, want it to carry the message", got)
	}

	bare := &ProtocolError{HTTPStatus: 400, Code: CodeMalformedRequest}
	if got := bare.Error(); got == "" {
		t.Errorf("Error() with no message returned empty string")
	}
}

func TestProtocolErrorReachableViaErrorsAs(t *testing.T) {
	wrapped := fmt.Errorf("submitting request: %w", NewProtocolError(CodeDuplicateRequest, "already seen"))

	var pe *ProtocolError
	if !errors.As(wrapped, &pe) {
		t.Fatal("errors.As did not find the wrapped ProtocolError")
	}
	if pe.Code != CodeDuplicateRequest {
		t.Errorf("Code = %q, want %q", pe.Code, CodeDuplicateRequest)
	}
}

func TestIsRetryableProtocolError(t *testing.T) {
	if IsRetryable(NewProtocolError(CodeMalformedRequest, "")) {
		t.Error("a 400 ProtocolError was reported retryable")
	}
	if IsRetryable(NewProtocolError(CodeInvalidSignature, "")) {
		t.Error("a 401 ProtocolError was reported retryable")
	}

	serverErr := &ProtocolError{HTTPStatus: http.StatusServiceUnavailable, Code: Code("hub_unavailable")}
	if !IsRetryable(serverErr) {
		t.Error("a 5xx ProtocolError was reported not retryable")
	}
}

func TestIsRetryableNonProtocolError(t *testing.T) {
	if IsRetryable(errors.New("boom")) {
		t.Error("a plain error was reported retryable")
	}
	if IsRetryable(nil) {
		t.Error("nil was reported retryable")
	}
}

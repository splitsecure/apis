package stepauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
)

// Code is a StepAuth error code.
type Code string

// Protocol error codes and their HTTP status.
const (
	CodeApproverSetTooLarge   Code = "approver_set_too_large"
	CodeDuplicateRequest      Code = "duplicate_request"
	CodeInvalidCallbackURL    Code = "invalid_callback_url"
	CodeInvalidSignature      Code = "invalid_signature"
	CodeMalformedRequest      Code = "malformed_request"
	CodeOperatorDepthExceeded Code = "operator_depth_exceeded"
	CodeRequestNotFound       Code = "request_not_found"
	CodeTimestampOutOfRange   Code = "timestamp_out_of_range"
	CodeUnknownApprover       Code = "unknown_approver"
	CodeUnknownCategory       Code = "unknown_category"
	CodeUnknownSender         Code = "unknown_sender"
	CodeWrongRecipient        Code = "wrong_recipient"
)

var codeStatus = map[Code]int{
	CodeApproverSetTooLarge:   http.StatusBadRequest,
	CodeDuplicateRequest:      http.StatusConflict,
	CodeInvalidCallbackURL:    http.StatusBadRequest,
	CodeInvalidSignature:      http.StatusUnauthorized,
	CodeMalformedRequest:      http.StatusBadRequest,
	CodeOperatorDepthExceeded: http.StatusBadRequest,
	CodeRequestNotFound:       http.StatusNotFound,
	CodeTimestampOutOfRange:   http.StatusBadRequest,
	CodeUnknownApprover:       http.StatusBadRequest,
	CodeUnknownCategory:       http.StatusBadRequest,
	CodeUnknownSender:         http.StatusUnauthorized,
	CodeWrongRecipient:        http.StatusForbidden,
}

// ProtocolError is an error response from the hub, reachable from a wrapped
// error via errors.As.
type ProtocolError struct {
	HTTPStatus int
	Code       Code
	Message    string
}

// Error renders the code and status.
func (e *ProtocolError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("stepauth: %s (%d): %s", e.Code, e.HTTPStatus, e.Message)
	}
	return fmt.Sprintf("stepauth: %s (%d)", e.Code, e.HTTPStatus)
}

// NewProtocolError builds a ProtocolError for code, filling in HTTPStatus
// from the protocol table. An unrecognized code defaults to 400, per
// wire.lock's documented default, and is classified fail-closed by IsRetryable.
func NewProtocolError(code Code, message string) *ProtocolError {
	status, ok := codeStatus[code]
	if !ok {
		status = http.StatusBadRequest
	}
	return &ProtocolError{HTTPStatus: status, Code: code, Message: message}
}

// IsRetryable reports whether a caller can retry err unchanged: a
// transport-level failure, or a hub 5xx. Every other ProtocolError, including
// an unrecognized code, is not retryable.
func IsRetryable(err error) bool {
	var pe *ProtocolError
	if errors.As(err, &pe) {
		return pe.HTTPStatus >= http.StatusInternalServerError
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

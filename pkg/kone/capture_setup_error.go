package kone

// CaptureSetupError separates a translated recovery hint from raw OS details.
type CaptureSetupError struct {
	Code  string
	Cause error
}

func (e *CaptureSetupError) Error() string     { return e.Cause.Error() }
func (e *CaptureSetupError) Unwrap() error     { return e.Cause }
func (e *CaptureSetupError) ErrorCode() string { return e.Code }

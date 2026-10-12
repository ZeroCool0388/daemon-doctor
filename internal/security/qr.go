package security

import (
	"strings"

	"github.com/skip2/go-qrcode"
)

// QR renders payload as a terminal QR. The text payload is still printed
// beside it so a test or a phone can read the same bytes.
func QR(payload string) (string, error) {
	code, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(code.ToSmallString(false), "\n"), nil
}

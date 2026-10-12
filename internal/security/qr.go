package security

import (
	"fmt"
	"os"
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

// WriteQRPNG saves the same payload as the terminal QR. Pairing codes are
// short-lived; the file is private and an existing file is never overwritten.
func WriteQRPNG(payload, path string) error {
	data, err := qrcode.Encode(payload, qrcode.Medium, 512)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write pairing PNG: %w", err)
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return fmt.Errorf("write pairing PNG: %w", err)
	}
	return closeErr
}

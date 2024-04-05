package goech

import (
	"errors"
	"fmt"
)

var (
	ErrNotSupportedVersion = fmt.Errorf("goech: %d is the only supported version", DraftTLSESNI16)
	ErrInvalidLen          = errors.New("goech: invalid length")
)

type InvalidPublicNameLenError uint

func (length InvalidPublicNameLenError) Error() string {
	return fmt.Sprintf("goech: the length of public name (%d) must be: 0 < len <= 255", length)
}

type InvalidKEMError uint16

func (kem InvalidKEMError) Error() string {
	return fmt.Sprintf("goech: %d is not a valid KEM identifier", kem)
}

type InvalidKDFError uint16

func (kdf InvalidKDFError) Error() string {
	return fmt.Sprintf("goech: %d is not a valid KDF identifier", kdf)
}

type InvalidAEADError uint16

func (aead InvalidAEADError) Error() string {
	return fmt.Sprintf("goech: %d is not a valid AEAD identifier", aead)
}

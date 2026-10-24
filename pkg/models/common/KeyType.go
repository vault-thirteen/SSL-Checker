package cm

import (
	"crypto/x509"
	"strconv"
)

type KeyType byte

const (
	KeyType_RSA     = KeyType(x509.RSA)     // 1.
	KeyType_DSA     = KeyType(x509.DSA)     // 2.
	KeyType_ECDSA   = KeyType(x509.ECDSA)   // 3.
	KeyType_Ed25519 = KeyType(x509.Ed25519) // 4.
)

func (kt KeyType) IsValid() bool {
	switch kt {
	case KeyType_RSA, KeyType_DSA, KeyType_ECDSA, KeyType_Ed25519:
		return true
	default:
		return false
	}
}
func (kt KeyType) ToString() string {
	switch kt {
	case KeyType_RSA:
		return "RSA"
	case KeyType_DSA:
		return "DSA"
	case KeyType_ECDSA:
		return "ECDSA"
	case KeyType_Ed25519:
		return "Ed25519"
	default:
		return strconv.Itoa(int(kt))
	}
}

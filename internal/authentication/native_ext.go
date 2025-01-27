package authentication

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func PrivateKeyFromString(pemBlock string) (ECDHPrivateKey, error) {
	block, _ := pem.Decode([]byte(pemBlock))
	if block == nil {
		return nil, fmt.Errorf("%w: expected PEM encoding", ErrInvalidPrivateKey)
	}

	var ecdsaPrivateKey *ecdsa.PrivateKey

	if block.Type == "EC PRIVATE KEY" {
		var err error
		ecdsaPrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	} else {
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		if ecdsaPrivateKey, ok = privateKey.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("%w: only elliptic curve keys supported", ErrInvalidPrivateKey)
		}
	}

	if ecdsaPrivateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: only NIST-P256 keys supported", ErrInvalidPrivateKey)
	}
	return &NativeECDHKey{ecdsaPrivateKey}, nil
}

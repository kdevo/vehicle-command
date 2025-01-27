package protocol

import (
	"github.com/teslamotors/vehicle-command/internal/authentication"
)

func PrivateKeyFromString(pemBlock string) (ECDHPrivateKey, error) {
	return authentication.PrivateKeyFromString(pemBlock)
}

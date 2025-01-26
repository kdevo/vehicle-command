package account

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/teslamotors/vehicle-command/internal/authentication"
)

const TelemetryClientApp = "TelemetryClient"

func SignForFleet(key authentication.ECDHPrivateKey, app string, message jwt.MapClaims) (string, error) {
	if message == nil {
		return "", fmt.Errorf("message cannot be nil")
	}
	if app == "" {
		app = TelemetryClientApp
	}
	return authentication.SignMessageForFleet(key, app, message)
}

package main

import (
	vendor_radius "github.com/Doridian/oauth-jit-radius/radius"
	"layeh.com/radius"
)

func MikrotikMapper(packet *radius.Packet, info OAuthUserInfo) (bool, error) {
	if info.MikrotikGroup == "" {
		return false, nil
	}

	return true, vendor_radius.MikrotikGroup_AddString(packet, info.MikrotikGroup)
}

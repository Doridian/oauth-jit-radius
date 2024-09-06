package main

import (
	vendor_radius "github.com/Doridian/oauth-jit-radius/radius"
	"layeh.com/radius"
)

func MikrotikMapper(packet *radius.Packet, info OAuthUserInfo) (bool, error) {
	if len(info.MikrotikGroup) < 1 {
		return false, nil
	}

	return true, vendor_radius.MikrotikGroup_AddString(packet, info.MikrotikGroup[len(info.MikrotikGroup)-1])
}

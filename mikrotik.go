package main

import (
	"strings"

	vendor_radius "github.com/Doridian/oauth-jit-radius/radius"
	"layeh.com/radius"
)

func MikrotikMapper(packet *radius.Packet, info OAuthUserInfo) (bool, error) {
	mtikGroup := ""
	for _, claim := range info.Claims {
		if strings.HasPrefix(claim, "mikrotik_group_") {
			mtikGroup = claim[15:]
			break
		}
	}

	if mtikGroup == "" {
		return false, nil
	}

	return true, vendor_radius.MikrotikGroup_AddString(packet, mtikGroup)
}

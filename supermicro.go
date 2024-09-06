package main

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func SupermicroMapper(packet *radius.Packet, info OAuthUserInfo) (bool, error) {
	if info.SupermicroPermissions == "" {
		return false, nil
	}

	packet.Add(rfc2865.VendorSpecific_Type, radius.Attribute(info.SupermicroPermissions))
	return true, nil
}

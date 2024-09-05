package main

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func SupermicroMapper(packet *radius.Packet, info OAuthUserInfo) error {
	packet.Add(rfc2865.VendorSpecific_Type, radius.Attribute(info.SupermicroPermissions))
	return nil
}

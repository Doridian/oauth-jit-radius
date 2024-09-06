package main

import (
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func SupermicroMapper(packet *radius.Packet, info OAuthUserInfo) (bool, error) {
	smicroPerms := ""
	if info.HasClaim("supermicro_administrator") {
		smicroPerms = "H=4, I=4"
	} else if info.HasClaim("supermicro_operator") {
		smicroPerms = "H=3, I=3"
	} else if info.HasClaim("supermicro_user") {
		smicroPerms = "H=2, I=2"
	} else if info.HasClaim("supermicro_noaccess") {
		smicroPerms = "H=1, I=1"
	} else {
		return false, nil
	}

	if smicroPerms == "" {
		return false, nil
	}

	packet.Add(rfc2865.VendorSpecific_Type, radius.Attribute(smicroPerms))
	return true, nil
}

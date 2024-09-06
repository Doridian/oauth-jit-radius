package main

import (
	vendor_radius "github.com/Doridian/oauth-jit-radius/radius"
	"layeh.com/radius"
)

func APCMapper(packet *radius.Packet, info OAuthUserInfo) (bool, error) {
	var apcServiceType vendor_radius.APCServiceType
	if info.HasClaim("apc_admin") {
		apcServiceType = vendor_radius.APCServiceType_Value_Admin
	} else if info.HasClaim("apc_device") {
		apcServiceType = vendor_radius.APCServiceType_Value_Device
	} else if info.HasClaim("apc_readonly") {
		apcServiceType = vendor_radius.APCServiceType_Value_ReadOnly
	} else {
		return false, nil
	}

	return true, vendor_radius.APCServiceType_Set(packet, apcServiceType)
}

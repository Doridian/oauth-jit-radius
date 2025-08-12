package main

import (
	vendor_radius "github.com/Doridian/oauth-jit-radius/radius"
	"layeh.com/radius"
)

func CyberPowerMapper(packet *radius.Packet, info *OAuthUserInfo) (bool, error) {
	var cyberServiceType vendor_radius.CyberPowerServiceType
	if HasClaim(info.CyberPowerServiceType, "admin") {
		cyberServiceType = vendor_radius.CyberPowerServiceType_Value_Admin
	} else if HasClaim(info.CyberPowerServiceType, "viewer") {
		cyberServiceType = vendor_radius.CyberPowerServiceType_Value_Viewer
	} else if HasClaim(info.CyberPowerServiceType, "outlet") {
		cyberServiceType = vendor_radius.CyberPowerServiceType_Value_Outlet
	} else {
		return false, nil
	}

	return true, vendor_radius.CyberPowerServiceType_Set(packet, cyberServiceType)
}

package main

import (
	"strings"

	vendor_radius "github.com/Doridian/oauth-jit-radius/radius"
	"layeh.com/radius"
)

func APCMapper(packet *radius.Packet, info OAuthUserInfo) (bool, error) {
	var apcServiceType vendor_radius.APCServiceType
	if HasClaim(info.APCServiceType, "admin") {
		apcServiceType = vendor_radius.APCServiceType_Value_Admin
	} else if HasClaim(info.APCServiceType, "device") {
		apcServiceType = vendor_radius.APCServiceType_Value_Device
	} else if HasClaim(info.APCServiceType, "outlet") {
		apcServiceType = vendor_radius.APCServiceType_Value_Outlet
	} else if HasClaim(info.APCServiceType, "network-only") {
		apcServiceType = vendor_radius.APCServiceType_Value_NetworkOnly
	} else if HasClaim(info.APCServiceType, "readonly") {
		apcServiceType = vendor_radius.APCServiceType_Value_ReadOnly
	} else {
		return false, nil
	}

	if len(info.APCOutlets) > 0 {
		outletsStr := strings.Join(info.APCOutlets, ",")
		if err := vendor_radius.APCOutlets_SetString(packet, outletsStr); err != nil {
			return false, err
		}
	}

	return true, vendor_radius.APCServiceType_Set(packet, apcServiceType)
}

package main

import (
	"strings"

	vendor_radius "github.com/Doridian/oauth-jit-radius/radius"
	"layeh.com/radius"
)

func APCMapper(packet *radius.Packet, info OAuthUserInfo) (bool, error) {
	if info.APCServiceType == "" {
		return false, nil
	}

	var apcServiceType vendor_radius.APCServiceType
	switch strings.ToLower(info.APCServiceType) {
	case "admin":
		apcServiceType = vendor_radius.APCServiceType_Value_Admin
	case "device":
		apcServiceType = vendor_radius.APCServiceType_Value_Device
	case "readonly":
		apcServiceType = vendor_radius.APCServiceType_Value_ReadOnly
	default:
		return false, nil
	}

	return true, vendor_radius.APCServiceType_Set(packet, apcServiceType)
}

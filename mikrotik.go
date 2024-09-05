package main

import (
	vendor_radius "github.com/Doridian/foxRADIUS/radius"
	"layeh.com/radius"
)

func MikrotikMapper(packet *radius.Packet, info OAuthUserInfo) error {
	return vendor_radius.MikrotikGroup_AddString(packet, info.MikrotikGroup)
}

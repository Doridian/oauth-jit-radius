package main

import (
	"context"
	"log"
	"net"
	"os"
	"reflect"
	"sync"

	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2868"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc3079"
	"layeh.com/radius/vendors/microsoft"
)

// Thanks to: https://github.com/holoplot/radioauth/blob/7caeddc60e4c597f812b86f446626f6836728581/cmd/radioauth/radius-server.go#L36

type RadiusMatcher struct {
	Subnets      []net.IPNet
	Secret       string
	CustomMapper func(*radius.Packet, OAuthUserInfo) (bool, error)
}

type RadiusMatcherList struct {
	matchers  []*RadiusMatcher
	cache     map[string]*RadiusMatcher
	cacheLock sync.RWMutex
}

// TODO: All of this should be configurable
var radiusMatchers = RadiusMatcherList{
	matchers: []*RadiusMatcher{
		{
			Subnets: []net.IPNet{
				{
					IP:   net.IP{10, 2, 1, 1},
					Mask: net.IPMask{255, 255, 255, 255},
				},
				{
					IP:   net.IP{10, 2, 1, 2},
					Mask: net.IPMask{255, 255, 255, 255},
				},
			},
			Secret:       os.Getenv("RADIUS_SECRET_MIKROTIK"),
			CustomMapper: MikrotikMapper,
		},
		{
			Subnets: []net.IPNet{
				{
					IP:   net.IP{10, 1, 12, 1},
					Mask: net.IPMask{255, 255, 255, 255},
				},
			},
			Secret:       os.Getenv("RADIUS_SECRET_SUPERMICRO"),
			CustomMapper: SupermicroMapper,
		},
		{
			Subnets: []net.IPNet{
				{
					IP:   net.IP{10, 1, 11, 2},
					Mask: net.IPMask{255, 255, 255, 255},
				},
			},
			Secret:       os.Getenv("RADIUS_SECRET_APCUPS"),
			CustomMapper: APCMapper,
		},
		{
			Subnets: []net.IPNet{
				{
					IP:   net.IP{10, 1, 11, 3},
					Mask: net.IPMask{255, 255, 255, 255},
				},
			},
			Secret:       os.Getenv("RADIUS_SECRET_CYBERPOWER"),
			CustomMapper: CyberPowerMapper,
		},
	},
	cache: make(map[string]*RadiusMatcher),
}

func (m *RadiusMatcherList) GetRadiusMatcherFor(remoteAddr net.Addr) *RadiusMatcher {
	remoteIP := remoteAddr.(*net.UDPAddr).IP
	cacheKey := remoteIP.String()

	m.cacheLock.RLock()
	foundMatcher, ok := m.cache[cacheKey]
	m.cacheLock.RUnlock()
	if ok {
		return foundMatcher
	}

	for _, matcher := range m.matchers {
		for _, subnet := range matcher.Subnets {
			if subnet.Contains(remoteIP) {
				m.cacheLock.Lock()
				m.cache[cacheKey] = matcher
				m.cacheLock.Unlock()
				return matcher
			}
		}
	}

	return nil
}

func (m *RadiusMatcherList) RADIUSSecret(ctx context.Context, remoteAddr net.Addr) ([]byte, error) {
	matcher := m.GetRadiusMatcherFor(remoteAddr)
	if matcher != nil {
		return []byte(matcher.Secret), nil
	}
	return nil, nil
}

func radiusMatchAndSendReply(w radius.ResponseWriter, r *radius.Request, userInfo OAuthUserInfo, packet *radius.Packet) {
	matcher := radiusMatchers.GetRadiusMatcherFor(r.RemoteAddr)
	if matcher == nil || matcher.CustomMapper == nil {
		_ = w.Write(packet)
		return
	}

	ok, err := matcher.CustomMapper(packet, userInfo)
	if err != nil {
		log.Printf("CustomMapper failed for %s: %v", userInfo.Username, err)
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if !ok {
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	_ = w.Write(packet)
}

func radiusHandler(w radius.ResponseWriter, r *radius.Request) {
	username := rfc2865.UserName_GetString(r.Packet)
	password := rfc2865.UserPassword_GetString(r.Packet)

	userInfo, err := GetUserInfoForUser(username)
	if err != nil {
		log.Printf("Cannot get user info for %s: %v", username, err)
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if userInfo.Username != username || userInfo.token == "" {
		_ = w.Write(r.Response(radius.CodeAccessReject))
		return
	}

	if password == userInfo.token {
		responsePacket := r.Response(radius.CodeAccessAccept)
		radiusMatchAndSendReply(w, r, userInfo, responsePacket)
		return
	}

	challenge := microsoft.MSCHAPChallenge_Get(r.Packet)
	response := microsoft.MSCHAP2Response_Get(r.Packet)

	if len(challenge) == 16 && len(response) == 50 {
		// See rfc2548 - 2.3.2. MS-CHAP2-Response
		ident := response[0]
		peerChallenge := response[2:18]
		peerResponse := response[26:50]
		ntResponse, err := rfc2759.GenerateNTResponse(challenge, peerChallenge, []byte(username), []byte(userInfo.token))
		if err != nil {
			log.Printf("Cannot generate ntResponse for %s: %v", username, err)
			_ = w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		if !reflect.DeepEqual(ntResponse, peerResponse) {
			_ = w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		responsePacket := r.Response(radius.CodeAccessAccept)

		recvKey, err := rfc3079.MakeKey(ntResponse, []byte(userInfo.token), false)
		if err != nil {
			log.Printf("Cannot make recvKey for %s: %v", username, err)
			_ = w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		sendKey, err := rfc3079.MakeKey(ntResponse, []byte(userInfo.token), true)
		if err != nil {
			log.Printf("Cannot make sendKey for %s: %v", username, err)
			_ = w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		authenticatorResponse, err := rfc2759.GenerateAuthenticatorResponse(challenge, peerChallenge, ntResponse, []byte(username), []byte(userInfo.token))
		if err != nil {
			log.Printf("Cannot generate authenticator response for %s: %v", username, err)
			_ = w.Write(r.Response(radius.CodeAccessReject))
			return
		}

		success := make([]byte, 43)
		success[0] = ident
		copy(success[1:], authenticatorResponse)

		_ = rfc2869.AcctInterimInterval_Add(responsePacket, rfc2869.AcctInterimInterval(3600))
		_ = rfc2868.TunnelType_Add(responsePacket, 0, rfc2868.TunnelType_Value_L2TP)
		_ = rfc2868.TunnelMediumType_Add(responsePacket, 0, rfc2868.TunnelMediumType_Value_IPv4)
		_ = microsoft.MSCHAP2Success_Add(responsePacket, []byte(success))
		_ = microsoft.MSMPPERecvKey_Add(responsePacket, recvKey)
		_ = microsoft.MSMPPESendKey_Add(responsePacket, sendKey)
		_ = microsoft.MSMPPEEncryptionPolicy_Add(responsePacket, microsoft.MSMPPEEncryptionPolicy_Value_EncryptionAllowed)
		_ = microsoft.MSMPPEEncryptionTypes_Add(responsePacket, microsoft.MSMPPEEncryptionTypes_Value_RC440or128BitAllowed)

		radiusMatchAndSendReply(w, r, userInfo, responsePacket)
		return
	}

	_ = w.Write(r.Response(radius.CodeAccessReject))
}

func startRadiusServer() {
	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(radiusHandler),
		SecretSource: &radiusMatchers,
	}

	log.Printf("Starting server on :1812")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

package http

import (
	"fmt"
	"github.com/google/gopacket"
)

type PacketKey struct {
	Net, Transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k PacketKey) String() string {
	return fmt.Sprintf("%v:%v", k.Net, k.Transport)
}


type CombineHttpRecord struct{
	Pk PacketKey
	Req string
	Resp string

	BytesIn string
	BytesOut string
	ClientIp string
	ClientPort string
	HttpResponseCode string
	Ip string
	Method string
	Path string
	Port string
	Query string
	Responsetime string
	Status string
}

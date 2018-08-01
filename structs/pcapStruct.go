package structs


type PcapStruct struct {
	Ethernet
	Network
	Transfer
	Http
}


/*type PcapStruct struct {
	SrcMac string
	DstMAC string
	EthernetType string


	SrcIP string
	DstIP string
	Protocol string


	SrcPort string
	DstPort string
	Seq string


	Method string
	Payload string
}*/

type Ethernet struct {
	SrcMac string
	DstMAC string
	EthernetType string
}

type Network struct {
	SrcIP string
	DstIP string
	Protocol string
}

type Transfer struct {
	SrcPort string
	DstPort string
	Seq string


}

type Http struct {
	Method string
	Payload string
}



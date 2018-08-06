package anaylysis

import (
	"fmt"
	"log"
	//"reflect"
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/igaoliang/pcapbeat/structs"

	"github.com/igaoliang/pcapbeat/structs"
	"time"
)

func main() {
	/*path := "/Users/leo/Desktop/test.pcap"
	handler, err := pcap.OpenOffline(path)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())

	i := 0
	for packet := range packetSource.Packets() {

		i++

		// fmt.Println(i)

		x := printPacketInfo(packet)

		fmt.Printf("xxxxxx is : %+v\n", x)

		//printHttp(packet)
	}

	fmt.Println(i)*/




	packetChan := make(chan structs.PcapStruct,10)

	go AnalysisAndGenerate(packetChan)

	for x := range packetChan{
		fmt.Printf("*********************\n%+v\n",x)
		time.Sleep(1000 * time.Duration(time.Millisecond))
	}

}


func AnalysisAndGenerate(packetChan chan structs.PcapStruct) {
	//packetChan := make(chan structs.PcapStruct,10)

	//path := "/Users/leo/Desktop/test.pcap"
	path := "C:/Users/igaol/Desktop/tt.pcap"

	handler, err := pcap.OpenOffline(path)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())

	i := 0
	for packet := range packetSource.Packets() {

		i++

		x := printPacketInfo(packet)

		packetChan <- x

/*		if i>100 {
			break
		}*/

		fmt.Println(i)

	}




	//return packetChan
}



// 应用层
func printHttp(packet gopacket.Packet){
	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {

		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {

			fmt.Println(">>>>>>>>>>>>>>>>>>>")

			// fmt.Println("HTTP found!")
			//fmt.Println("Application layer/Payload found.")

			fmt.Printf("%s\n", applicationLayer.Payload())

			fmt.Println("<<<<<<<<<<<<<<<<<<<")

		}
	}
}


func printPacketInfo(packet gopacket.Packet) structs.PcapStruct{

	ps := structs.PcapStruct{
		Ethernet: structs.Ethernet{
			SrcMac:       "",
			DstMAC:       "",
			EthernetType: "",
		},
		Network: structs.Network{
			SrcIP:    "",
			DstIP:    "",
			Protocol: "",
		},
		Transfer: structs.Transfer{
			SrcPort: "",
			DstPort: "",
			Seq:     "",
		},
		Http: structs.Http{
			Method:  "",
			Payload: "",
		},
	}


	// 数据链路层
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {

		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		/*fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()*/

		ps.SrcMac = ethernetPacket.SrcMAC.String()
		ps.DstMAC = ethernetPacket.DstMAC.String()
		ps.EthernetType = ethernetPacket.EthernetType.String()

	}

	// 网络层
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		/*fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()*/

		ps.SrcIP = ip.SrcIP.String()
		ps.DstIP = ip.DstIP.String()
		ps.Protocol = ip.Protocol.String()

	}

	// 传输层
	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		//tcp, some := tcpLayer.(*layers.TCP)
		// tcp := tcpLayer
		/*fmt.Println(reflect.TypeOf(tcp), reflect.TypeOf(tcpLayer))
		// fmt.Println(tcpLayer)
		fmt.Println("some=", some)

		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		// fmt.Printf("From port %d to %d\n", tcpLayer.SrcPort, tcpLayer.DstPort)
		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()*/

		ps.SrcPort = fmt.Sprintf("%d",tcp.SrcPort)
		ps.DstPort = fmt.Sprintf("%d",tcp.DstPort)
		ps.Seq = fmt.Sprint(tcp.Seq)

	}

	// 应用层
	//payloadLayer = packet.Layer(layers)


	// Iterate over all layers, printing out each layer type
	/*fmt.Println("All packet layers:")
	for _, layer := range packet.Layers() {
		fmt.Println("- ", layer.LayerType())
	}*/


	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		//fmt.Println("Application layer/Payload found.")
		//
		//fmt.Println(">>>>>>>>>>>>>>>>>>>")
		//
		//fmt.Printf("%s\n", applicationLayer.Payload())
		//
		//fmt.Println("<<<<<<<<<<<<<<<<<<<")

		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")

			fmt.Println("Application layer/Payload found.")

			fmt.Println(">>>>>>>>>>>>>>>>>>>")

			fmt.Printf("%s\n", applicationLayer.Payload())

			fmt.Println("<<<<<<<<<<<<<<<<<<<")


			ps.Payload = string(applicationLayer.Payload())

		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}

	return ps
}

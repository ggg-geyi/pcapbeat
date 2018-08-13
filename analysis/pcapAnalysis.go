package analysis
//package main

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
	"github.com/igaoliang/pcapbeat/utils"
	"github.com/elastic/beats/libbeat/common"
	"time"
)


// 用来保存request的数据流
var reqMap = make(map[structs.PacketKey]structs.CombineHttpRecord)

// 用来保存response的数据流
var respMap = make(map[structs.PacketKey]structs.CombineHttpRecord)

func main() {

	packetChan := make(chan structs.CombineHttpRecord,10)

	go AnalysisAndGenerate(packetChan)

	/*for x := range packetChan{
		fmt.Printf("*********************\n%+v\n",x)
		//time.Sleep(1000 * time.Duration(time.Millisecond))
	}*/


	idx := 0

	for v := range packetChan{

		time.Sleep(10 * time.Millisecond)

		idx ++

		fmt.Printf("========================================================\n " +
			"clent:%s,  server:%s  srcPort:%s,  destPort:%s \n" +
			"key %+v \n req\n %+v \n resp\n %+v \n", v.Pk.Net.Src(), v.Pk.Net.Dst(),v.Pk.Transport.Src(),v.Pk.Transport.Dst(),v.Pk, v.Req, v.Resp)

		fmt.Printf(">>>> mapstr: %s\n", common.MapStr{
			"client_ip": v.Pk.Net.Src().String(),
			"server": v.Pk.Net.Dst().String(),
			"client_port":v.Pk.Transport.Src().String(),
			"port":v.Pk.Transport.Dst().String(),
			"http":common.MapStr{
				"response":common.MapStr{
					"code":v.HttpResponseCode,
				},
			},

			"status": v.Status,
			"bytes_in": v.BytesIn,
			"bytes_out": v.BytesOut,
			"path": v.Path,
			"method": v.Method,
			"responsetime": v.Responsetime,
		})

		fmt.Printf("AAAAAAAAAAAAAAAAAAAAAAAAAidx is : %d and map size is : %d\n", idx, len(reqMap))
	}
}


func AnalysisAndGenerate(packetChan chan structs.CombineHttpRecord){
	//packetChan := make(chan structs.PcapStruct,10)

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

		combineHttp(packet)

	}

	fmt.Println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

	idx := 0

	for _, v := range reqMap{

		idx ++

		packetChan <- v

		/*fmt.Printf("========================================================\n " +
			"clent:%s,  server:%s  srcPort:%s,  destPort:%s \n" +
			"key %+v \n req\n %+v \n resp\n %+v \n", k.Net.Src(), k.Net.Dst(),k.Transport.Src(),k.Transport.Dst(),k, v.Req, v.Resp)

		fmt.Printf(">>>> mapstr: %s\n", common.MapStr{
			"client": k.Net.Src().String(),
			"server": k.Net.Dst().String(),
			"client_port":k.Transport.Src().String(),
			"port":k.Transport.Dst().String(),
			"http":common.MapStr{
				"response":common.MapStr{
					"code":v.HttpResponseCode,
				},
			},

			"status": v.Status,
			"bytes_in": v.BytesIn,
			"bytes_out": v.BytesOut,
			"path": v.Path,
			"method": v.Method,
			"responsetime": v.Responsetime,
		})


		fmt.Printf("tttttttttttttttttttttttttttidx is : %d and map size is : %d", idx, len(reqMap))*/

		fmt.Printf("tttttttttttttttttttttttttttidx is : %d and map size is : %d\n", idx, len(reqMap))

	}



	/*fmt.Println("===============================================ready close channel.........")

	close(packetChan)

	fmt.Println("===============================================after close channel.........")*/

}


func AnalysisAndGeneratex(packetChan chan structs.PcapStruct) {
	//packetChan := make(chan structs.PcapStruct,10)

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

		combineHttp(packet)

		//fmt.Println(i)

	}

	fmt.Println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

	for k,v := range reqMap{
		fmt.Printf("========================================================\n " +
			"clent:%s,  server:%s  srcPort:%s,  destPort:%s \n" +
			"key %+v \n req\n %+v \n resp\n %+v \n", k.Net.Src(), k.Net.Dst(),k.Transport.Src(),k.Transport.Dst(),k, v.Req, v.Resp)

		fmt.Printf(">>>> mapstr: %s\n", common.MapStr{
			"client": k.Net.Src().String(),
			"server": k.Net.Dst().String(),
			"client_port":k.Transport.Src().String(),
			"port":k.Transport.Dst().String(),
			"http":common.MapStr{
				"response":common.MapStr{
					"code":v.HttpResponseCode,
				},
			},

			"status": v.Status,
			"bytes_in": v.BytesIn,
			"bytes_out": v.BytesOut,
			"path": v.Path,
			"method": v.Method,
			"responsetime": v.Responsetime,
		})
	}


	//return packetChan
}


func combineHttp(packet gopacket.Packet) structs.PcapStruct{

	//fmt.Println(">>>>>>>>>>>>>>>>>>>")

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
		//fmt.Println("IPv4 layer detected.")
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
		//fmt.Println("TCP layer detected.")
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


	// When iterating through packet.Layers() above,
	// if it lists Payload layer then that is the same as
	// this applicationLayer. applicationLayer contains the payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {

		payloadString := string(applicationLayer.Payload())

		if strings.Contains(payloadString, "HTTP") {

			fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

			isReq := false
			method := ""

			// 遍历http的4种方法，一旦匹配到立马退出
			for _, mthd := range utils.HttpMethodArray{
				if strings.Contains(payloadString, mthd){
					method = mthd
					isReq = true
					break
				}
			}

			items := strings.Split(payloadString," ")

			if len(items) >=2 {
				if isReq{
					/* request 信息流 内容信息样例如下
						GET /ibop/js/ligerUI/js/plugins/ligerGrid.js HTTP/1.1
						Accept:
						Refere
					*/
					fmt.Println("--------this is a req streams.and method is", method)
					fmt.Println(len(items))
					fmt.Println(items[0],"--",items[1])

					key := structs.PacketKey{Net:packet.NetworkLayer().NetworkFlow(),Transport:packet.TransportLayer().TransportFlow()}


					reqMap[key] = structs.CombineHttpRecord{Pk:key, Req:payloadString, ClientIp:key.Net.Src().String(),
						ClientPort:key.Transport.Src().String(), Method: items[0],
						Path:items[1], Port:key.Transport.Dst().String()}

				}else{
					/* response 服务器回应数据流
						HTTP/1.1 304 Not Modified
						Server: unknow
						Connection: close
						ETag: W/"22
					*/
					fmt.Println("-----------this is a resp streams.")
					fmt.Println(items[0],"--",items[1])

					key := structs.PacketKey{Net:packet.NetworkLayer().NetworkFlow().Reverse(),Transport:packet.TransportLayer().TransportFlow().Reverse()}

					if reqrecord,ok := reqMap[key] ; ok{
						// resp 流匹配到之前的request流.合并request 以及 response 的字段。
						//TODO 将request从map中删除。当同一个端口和服务器频繁交互的的时候，req 和 resp的匹配可能会混乱掉
						//req := reqrecord.req

						reqrecord.Resp = payloadString

						// 在合并流中附加response的信息
						reqrecord.HttpResponseCode=items[1]
						if status,ok := utils.HttpCodeSummary[items[1]] ; ok {
							reqrecord.Status = status
						}

						reqMap[key] = reqrecord

						fmt.Printf("**************** req\n %+v\n resp %+v\n", reqrecord.Req, reqrecord.Resp)

					}else{
						fmt.Println("not match")
					}
				}
			}

			//fmt.Println("........",payloadString)

			ps.Payload = string(applicationLayer.Payload())

		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}

	return ps
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

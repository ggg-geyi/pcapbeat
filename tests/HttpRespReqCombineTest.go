package main

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
)




type packetKey struct {
	net, transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k packetKey) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}


type combineHttpRecord struct{
	pk packetKey
	req string
	resp string

	bytesIn string
	bytesOut string
	clientIp string
	clientPort string
	httpResponseCode string
	ip string
	method string
	path string
	port string
	query string
	responsetime string
	status string
}

// 用来保存request的数据流
var reqMap = make(map[packetKey]combineHttpRecord)

// 用来保存response的数据流
var respMap = make(map[packetKey]combineHttpRecord)

func main() {

	packetChan := make(chan structs.PcapStruct,10)

	go AnalysisAndGenerate(packetChan)

	for x := range packetChan{
		fmt.Printf("*********************\n%+v\n",x)
		//time.Sleep(1000 * time.Duration(time.Millisecond))
	}

}


func AnalysisAndGenerate(packetChan chan structs.PcapStruct) {

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

		/*x := printPacketInfo(packet)

		packetChan <- x*/


		combineHttp(packet)

		//fmt.Println(i)

	}

	fmt.Println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

	for k,v := range reqMap{
		fmt.Printf("========================================================\n " +
			"clent:%s,  server:%s  srcPort:%s,  destPort:%s \n" +
			"key %+v \n req\n %+v \n resp\n %+v \n", k.net.Src(), k.net.Dst(),k.transport.Src(),k.transport.Dst(),k, v.req, v.resp)

		fmt.Printf(">>>> mapstr: %s\n", common.MapStr{
			"client": k.net.Src().String(),
			"server": k.net.Dst().String(),
			"client_port":k.transport.Src().String(),
			"port":k.transport.Dst().String(),
			"http":common.MapStr{
				"response":common.MapStr{
					"code":v.httpResponseCode,
				},
			},

			"status": v.status,
			"bytes_in": v.bytesIn,
			"bytes_out": v.bytesOut,
			"path": v.path,
			"method": v.method,
			"responsetime": v.responsetime,
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

					key := packetKey{net:packet.NetworkLayer().NetworkFlow(),transport:packet.TransportLayer().TransportFlow()}


					reqMap[key] = combineHttpRecord{pk:key, req:payloadString, clientIp:key.net.Src().String(),
										clientPort:key.transport.Src().String(), method: items[0],
										path:items[1], port:key.transport.Dst().String()}

				}else{
					/* response 服务器回应数据流
						HTTP/1.1 304 Not Modified
						Server: unknow
						Connection: close
						ETag: W/"22
					*/
					fmt.Println("-----------this is a resp streams.")
					fmt.Println(items[0],"--",items[1])

					key := packetKey{net:packet.NetworkLayer().NetworkFlow().Reverse(),transport:packet.TransportLayer().TransportFlow().Reverse()}

					if reqrecord,ok := reqMap[key] ; ok{
						// resp 流匹配到之前的request流.合并request 以及 response 的字段。
						//TODO 将request从map中删除。当同一个端口和服务器频繁交互的的时候，req 和 resp的匹配可能会混乱掉
						//req := reqrecord.req

						reqrecord.resp = payloadString

						// 在合并流中附加response的信息
						reqrecord.httpResponseCode=items[1]
						if status,ok := utils.HttpCodeSummary[items[1]] ; ok {
							reqrecord.status = status
						}

						reqMap[key] = reqrecord

						fmt.Printf("**************** req\n %+v\n resp %+v\n", reqrecord.req, reqrecord.resp)

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

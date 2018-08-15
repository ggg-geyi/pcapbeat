package http

import (
	"github.com/igaoliang/pcapbeat/utils"
	"github.com/google/gopacket"
	"strings"
	"github.com/elastic/beats/libbeat/logp"
)

func CombineReqAndResp(packet gopacket.Packet, reqMap map[PacketKey]CombineHttpRecord){
	applicationLayer := packet.ApplicationLayer()

	if applicationLayer != nil {
		payloadString := string(applicationLayer.Payload())

		if strings.Contains(payloadString, "HTTP") {
			isReq := false
			// 遍历http的4种方法，一旦匹配到立马退出
			for _, method := range utils.HttpMethodArray{
				if strings.Contains(payloadString, method){
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
					/*fmt.Println("--------this is a req streams.and method is", method)
					fmt.Println(len(items))
					fmt.Println(items[0],"--",items[1])*/

					key := PacketKey{Net:packet.NetworkLayer().NetworkFlow(),Transport:packet.TransportLayer().TransportFlow()}

					reqMap[key] = CombineHttpRecord{Pk:key, Req:payloadString, ClientIp:key.Net.Src().String(),
						ClientPort:key.Transport.Src().String(), Method: items[0],
						Path:items[1], Port:key.Transport.Dst().String()}

				}else{
					/* response 服务器回应数据流
						HTTP/1.1 304 Not Modified
						Server: unknow
						Connection: close
						ETag: W/"22
					*/
					/*fmt.Println("-----------this is a resp streams.")
					fmt.Println(items[0],"--",items[1])*/

					key := PacketKey{Net:packet.NetworkLayer().NetworkFlow().Reverse(),Transport:packet.TransportLayer().TransportFlow().Reverse()}

					if reqRecord,ok := reqMap[key] ; ok{
						// resp 流匹配到之前的request流.合并request 以及 response 的字段。
						//TODO 将request从map中删除。当同一个端口和服务器频繁交互的的时候，req 和 resp的匹配可能会混乱掉
						//req := reqrecord.req

						reqRecord.Resp = payloadString

						// 在合并流中附加response的信息
						reqRecord.HttpResponseCode=items[1]
						if status,ok := utils.HttpCodeSummary[items[1]] ; ok {
							reqRecord.Status = status
						}

						reqMap[key] = reqRecord

					}else{
						//fmt.Println("not match")
					}
				}
			}
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		logp.Info("Error decoding some part of the packet:", err)
	}
}


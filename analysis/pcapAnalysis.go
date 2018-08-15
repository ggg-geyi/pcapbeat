package analysis

import (
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/igaoliang/pcapbeat/protocols/http"
)

// 读取pcap文件的内容，并且处理特定协议的报文
func ReadPcapAndDealProtocols(packetChan chan http.CombineHttpRecord, filePath string){

	// 用来保存request的数据流
	var httpReqMap = make(map[http.PacketKey]http.CombineHttpRecord)

	path := filePath
	handler, err := pcap.OpenOffline(path)

	if err != nil {
		log.Fatal(err)
	}

	defer close(packetChan)
	defer handler.Close()

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		http.CombineReqAndResp(packet, httpReqMap)
	}

	for _, v := range httpReqMap{
		packetChan <- v
	}
}




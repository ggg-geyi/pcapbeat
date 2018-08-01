package beater

import (
	"fmt"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/igaoliang/pcapbeat/config"
	"github.com/igaoliang/pcapbeat/structs"
	"github.com/igaoliang/pcapbeat/analysis"
)

type Pcapbeat struct {
	done   chan struct{}
	config config.Config
	client beat.Client
}

// Creates beater
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config := config.DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Pcapbeat{
		done:   make(chan struct{}),
		config: config,
	}

	fmt.Printf("pcapfilepath is : %s\n", config.Filepath)

	return bt, nil
}

func (bt *Pcapbeat) Run(b *beat.Beat) error {
	logp.Info("pcapbeat is running! Hit CTRL-C to stop it.")

	var err error
	bt.client, err = b.Publisher.Connect()
	if err != nil {
		return err
	}

	packetChan := make(chan structs.PcapStruct,10)

	go analysis.AnalysisAndGenerate(packetChan)


	var idx = 0

	for x:= range packetChan{
		event := beat.Event{
			Timestamp: time.Now(),
			Fields: common.MapStr{
				"type":    b.Info.Name,
				"SrcMac": x.SrcMac,
				"DstMAC": x.DstMAC,
				"EthernetType": x.EthernetType,


				"SrcIP": x.SrcIP,
				"DstIP": x.DstIP,
				"Protocol": x.Protocol,


				"SrcPort": x.SrcPort,
				"DstPort": x.DstPort,
				"Seq": x.Seq,


				"Method": x.Method,
				"Payload": x.Payload,
			},
		}

		idx ++

		bt.client.Publish(event)
		logp.Info("Event sent", string(idx))
		fmt.Printf("Event sent %d \n", idx)

		idx = 0

	}

	close(packetChan)

	return nil
}

/*func (bt *Pcapbeat) Run(b *beat.Beat) error {
	logp.Info("pcapbeat is running! Hit CTRL-C to stop it.")

	var err error
	bt.client, err = b.Publisher.Connect()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(bt.config.Period)
	counter := 1
	for {
		select {
		case <-bt.done:
			return nil
		case <-ticker.C:
		}

		event := beat.Event{
			Timestamp: time.Now(),
			Fields: common.MapStr{
				"type":    b.Info.Name,
				"counter": counter,
			},
		}
		bt.client.Publish(event)
		logp.Info("Event sent")
		counter++
	}
}*/

func (bt *Pcapbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}

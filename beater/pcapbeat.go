package beater

import (
	"fmt"
	//"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/igaoliang/pcapbeat/config"
	"github.com/igaoliang/pcapbeat/structs"
	"time"
	"github.com/igaoliang/pcapbeat/analysis"
)

type Pcapbeat struct {
	done   chan struct{}
	config config.Config
	client beat.Client
}

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

	fmt.Printf("config content is : %s\n", config)

	return bt, nil
}



func (bt *Pcapbeat) Run(b *beat.Beat) error {
	logp.Info("pcapbeat is running! Hit CTRL-C to stop it.")

	var err error
	bt.client, err = b.Publisher.Connect()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(bt.config.Period)

	// TODO 这里可以控制是否并发处理数据。
	// 需要判断是否允许并发处理数据。意思是多余衣蛾的pcap文件可以被处理。
	// 为了简单方便，每次只允许处理一个pcap文件。如果调度周期到了，如果发现当前已经开始处理pcap文件了，那么跳出本次循环。
	for {
		select {
		case <-bt.done:
			return nil
		case <-ticker.C:
		}

		logp.Info("============================")

		packetChan := make(chan structs.CombineHttpRecord,10)

		defer close(packetChan)

		// 开启一个协程去处理数据
		go analysis.AnalysisAndGenerate(packetChan)

		var idx = 0

		// 开启协程准备发送数据
		go func() {
			for x := range packetChan {

				event := beat.Event{
					Timestamp: time.Now(),

					Fields: common.MapStr{
						//"type":        b.Info.Name,
						"type":        "http",   // 将协议类型自动修正为http
						"client_ip":   x.Pk.Net.Src().String(),
						"server":      x.Pk.Net.Dst().String(),
						"client_port": x.Pk.Transport.Src().String(),
						"port":        x.Pk.Transport.Dst().String(),
						"http": common.MapStr{
							"response": common.MapStr{
								"code": x.HttpResponseCode,
							},
						},

						"status":       x.Status,
						"bytes_in":     x.BytesIn,
						"bytes_out":    x.BytesOut,
						"path":         x.Path,
						"method":       x.Method,
						"responsetime": x.Responsetime,
					},
				}

				idx ++

				bt.client.Publish(event)
				logp.Info("Event sent %s", idx)
				//logp.Info("Event sent %s", event)
				fmt.Printf("Event sent %d \n", idx)
			}
			close(packetChan)
		}()
	}
}



/*
可以使用的版本。这个版本仅仅调用一次就退出。
可以作为测试功能是否正常的代码
 */
func (bt *Pcapbeat) runSingle(b *beat.Beat) error {
	logp.Info("pcapbeat is running! Hit CTRL-C to stop it.")

	var err error
	bt.client, err = b.Publisher.Connect()
	if err != nil {
		return err
	}

	packetChan := make(chan structs.CombineHttpRecord,10)

	defer close(packetChan)

	go analysis.AnalysisAndGenerate(packetChan)

	for x:= range packetChan{

		event := beat.Event{
			Timestamp: time.Now(),

			Fields : common.MapStr{
				"type":    b.Info.Name,
				"client_ip": x.Pk.Net.Src().String(),
				"server": x.Pk.Net.Dst().String(),
				"client_port":x.Pk.Transport.Src().String(),
				"port":x.Pk.Transport.Dst().String(),
				"http":common.MapStr{
					"response":common.MapStr{
						"code":x.HttpResponseCode,
					},
				},

				"status": x.Status,
				"bytes_in": x.BytesIn,
				"bytes_out": x.BytesOut,
				"path": x.Path,
				"method": x.Method,
				"responsetime": x.Responsetime,
			},
		}

		bt.client.Publish(event)
	}

	close(packetChan)

	return nil
}


/*
原始的自动生成的run方法
 */
func (bt *Pcapbeat) runBak(b *beat.Beat) error {
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
}

func (bt *Pcapbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}

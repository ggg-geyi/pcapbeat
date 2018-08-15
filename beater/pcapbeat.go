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
	"sync"
	"github.com/igaoliang/pcapbeat/utils"
)

type Pcapbeat struct {
	done   chan struct{}
	config config.Config
	client beat.Client
}

// 记录正在开始处理的map.使用线程安全类型。
// 主要是协程并发读取文件系统的时候，可能会出现重复选中同一个文件的问题。每次要开始处理文件的时候，都检查下是否正常。
var dealingMap sync.Map

var maxConcurrent = 100

var count = 0

func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config := config.DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Pcapbeat{
		done:   make(chan struct{}),
		config: config,
	}


	// 创建控制全局并发的chan。当协程开始处理pcap文件的时候，写入这个chan。当处理完毕的时候，从这个chan读出数据
	maxConcurrent = 100

	if config.Concurrentcount <100 || config.Concurrentcount >0 {
		maxConcurrent = int(config.Concurrentcount)
	}

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

		// 到达调度周期，开始准备处理数据
		// 1.判断全局并发是否阻塞，如果阻塞，那么不开始处理数据。
		// 2.开始获取数据执行处理。

		filePathList, err := utils.FetchNumberFolderFile(bt.config.Pcapfilefolder, ".pcap", maxConcurrent)

		if err != nil{
			logp.Err("查找pcap文件报错")
			continue
		}

		if len(filePathList) == 0{
			logp.Warn("未找到pcap文件，跳过处理")
			continue
		}

		for index, filePath := range filePathList{

			/*// 当前文件已经在处理了。需要跳过这个文件。如果吧处理的文件命名成.dealing的话，那么将该逻辑取消
			if _, ok := dealingMap.Load(filePath) ; !ok{
				logp.Info("当前文件已经在处理了，跳过。", filePath)
				continue
			}*/

			// 文件可以处理。
			logp.Info("============================")

			newPath := ""

			if path, error := utils.RenamePcapFileToDealing(filePath); error != nil{
				logp.Err("将当前pcap文件改为dealing报错。",error.Error())
				continue
			}else{

				fmt.Println("...... newpaht ： ", newPath)

				newPath = path
			}

			logp.Info("开始启动第 >{}< 个协程处理数据... %s", index, filePath)

			packetChan := make(chan structs.CombineHttpRecord,10)

			//defer close(packetChan)

			// 开启一个协程去处理数据
			go analysis.AnalysisAndGenerate(packetChan, newPath)

			// 开启协程准备发送数据
			go func(newPath string, packetChan chan structs.CombineHttpRecord) {
				for x := range packetChan {

					event := beat.Event{
						Timestamp: time.Now(),

						Fields: common.MapStr{
							//"type":        b.Info.Name,
							"type":        "http",   // 将协议类型自动修正为http
							"filepath": filePath,
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

					bt.client.Publish(event)
					//logp.Info("Event sent %s", idx)
					//logp.Info("Event sent %s", event)
					//fmt.Printf("Event sent %d \n", idx)
				}


				fmt.Println("开始准备deal--》done")
				if _, error := utils.RenamePcapDealingFileToDone(newPath); error != nil{
					logp.Err("将当前pcap.dealing文件改为done报错。路径以及报凑信息为",newPath,error.Error())
				}

				fmt.Println("结束deal--》done")

			}(newPath, packetChan)
		}


	}
}


func (bt *Pcapbeat) Runx(b *beat.Beat) error {
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

		// 到达调度周期，开始准备处理数据
		// 1.判断全局并发是否阻塞，如果阻塞，那么不开始处理数据。
		// 2.开始获取数据执行处理。
		//globalConcurrentChan <- true

		count ++

		logp.Info("XXXXXXXXXXXXXXXXXXXXXX --> ", count)



		logp.Info("============================")

		packetChan := make(chan structs.CombineHttpRecord,10)

		defer close(packetChan)

		// 开启一个协程去处理数据
		go analysis.AnalysisAndGenerate(packetChan, "")

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
				//logp.Info("Event sent %s", idx)
				//logp.Info("Event sent %s", event)
				//fmt.Printf("Event sent %d \n", idx)
			}

			logp.Info("数据发送完毕，数据状态。。" )

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

	go analysis.AnalysisAndGenerate(packetChan, "")

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

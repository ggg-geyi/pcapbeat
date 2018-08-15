package beater

import (
	"fmt"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/igaoliang/pcapbeat/config"
	"time"
	"github.com/igaoliang/pcapbeat/analysis"
	"github.com/igaoliang/pcapbeat/utils"
	"github.com/igaoliang/pcapbeat/protocols/http"
)

type Pcapbeat struct {
	done   chan struct{}
	config config.Config
	client beat.Client
}

// 用来控制每个周期处理的最大并发参数。默认100.放置设置的不合理。限制在1-100之内
// 防止配置文件配置错误开启太多协程。正常情况下100个够用
var maxConcurrent = 100

func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config := config.DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Pcapbeat{
		done:   make(chan struct{}),
		config: config,
	}

	if config.Concurrentcount <100 || config.Concurrentcount >0 {
		maxConcurrent = int(config.Concurrentcount)
	}

	logp.Info("config content is : ", fmt.Sprintf("%+v", config))

	return bt, nil
}


func (bt *Pcapbeat) Run(b *beat.Beat) error {
	logp.Info("pcapbeat is running! Hit CTRL-C to stop it.")

	var err error
	bt.client, err = b.Publisher.Connect()
	if err != nil {
		return err
	}

	deleteTaskFlag := bt.config.DeleteTaskFlag

	ticker := time.NewTicker(bt.config.Period)
	for {
		select {
		case <-bt.done:
			return nil
		case <-ticker.C:
		}

		if deleteTaskFlag {
			// 针对系统而言，如果任务都被删除了，那么程序将按照特定的周期空跑。
			// 主要是为了检查方便，程序空跑的时候，进程还在，可以探测进程是否正常
			logp.Warn("deltetaskflag is true.so continue and wait next period........")
			continue
		}

		// 从配置文件中指明的监听路径中获取pcap后缀的文件。然后返回给待处理的对象
		filePathSlice, err := utils.FetchNumberFolderFile(bt.config.Pcapfilefolder, ".pcap", maxConcurrent)
		if err != nil{
			logp.Err("FIND AND LIST PCAP FILE ERROR. AND FOLDER IS : ", bt.config.Pcapfilefolder)
			continue
		}

		if len(filePathSlice) == 0{
			logp.Warn("THERE IS NO PCAP FILE IN FOLDER.SO CONTINUE.FOLDER IS : ", bt.config.Pcapfilefolder)
			continue
		}

		for index, filePath := range filePathSlice{
			logp.Info("=========== READY DEAL PCAP FILE =======")
			newPath := ""

			// 先将文件重命名dealing。标示这个文件正在被处理
			if path, error := utils.RenamePcapFileToDealing(filePath); error != nil{
				logp.Err("RENAME .PCAP TO .DEALING ERROR.ERROR MSG IS : 。",error.Error())
				continue
			}else{
				newPath = path
				logp.Info("RENAME .PCAP TO .DEALING ", filePath, "  ---> ",newPath)
			}
			logp.Info("REANDY DEALING FILE PATH IS : ", index, filePath)

			// 创建带缓冲的chan。这个chan用来存放的就是http的req和resp合并之后的记录
			packetChan := make(chan http.CombineHttpRecord,10)

			// 开启一个协程去处理数据
			go analysis.ReadPcapAndDealProtocols(packetChan, newPath)

			// 开启协程准备发送数据
			go func(newPath string, packetChan chan http.CombineHttpRecord) {
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
				}

				logp.Info("READY TO RENAME .dealing TO .done",newPath)
				if _, error := utils.RenamePcapDealingFileToDone(newPath); error != nil{
					logp.Err("RENAME .dealing TO .done ERROR. PATH IS : ",newPath,"  AND MESSAGE IS : ",error.Error())
				}else{
					logp.Info("DONE RENAME .dealing TO .done",newPath)
				}

			}(newPath, packetChan)
		}
	}
}

func (bt *Pcapbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}

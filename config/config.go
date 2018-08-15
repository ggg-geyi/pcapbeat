// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

import "time"

type Config struct {
	Period time.Duration `config:"period"`
	Pcapfilefolder string `config:"pcapfilefolder"`
	Concurrentcount uint `config:"concurrentcount"`
}

var DefaultConfig = Config{
	// 默认时间1分钟
	Period: 1 * time.Minute,
	Pcapfilefolder: "./pcap",
	Concurrentcount: 5,
}

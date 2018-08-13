// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

import "time"

type Config struct {
	Period time.Duration `config:"period"`
	Filepath string `config:"filepath"`
	Pcapfilefolder string `config:"pcapfilefolder"`
}

var DefaultConfig = Config{
	// 默认时间1分钟
	Period: 1 * time.Minute,
	Filepath: "/Users/leo/Desktop/test.pcap",
	Pcapfilefolder: "./pcap",
}

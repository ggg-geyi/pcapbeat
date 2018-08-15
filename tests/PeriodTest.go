package main

import (
	"time"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"container/list"
)

func main() {

	ticker := time.NewTicker(1 * time.Second)

	dirpath := "C:/Users/igaol/Desktop"

	PthSep := string(os.PathSeparator)

	tt := make([]string, 5)

	for {
		select {
		case <- ticker.C:
		}

		tt = append(tt, time.Now().Format("2006-01-02 15:04:05"))

		fmt.Println(tt)

		fmt.Println("======================================================")

		fmt.Println(time.Now().Format("2006-01-02 15:04:05"))

		dir, err := ioutil.ReadDir(dirpath)
		if err != nil {
			panic(err)
		}

		for _, it := range dir{
			if strings.HasSuffix(it.Name(),".pcap"){
				fmt.Println(dirpath + PthSep + it.Name())
			}
		}

	}
}


func test() *list.List{
	return list.New()
}

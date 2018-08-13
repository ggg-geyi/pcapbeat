package main

import (
	"time"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {

	ticker := time.NewTicker(5 * time.Second)

	dirpath := "C:/Users/igaol/Desktop"

	PthSep := string(os.PathSeparator)

	for {
		select {
		case <- ticker.C:
		}

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

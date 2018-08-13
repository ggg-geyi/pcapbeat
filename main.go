package main

import (
	"os"

	"github.com/igaoliang/pcapbeat/cmd"
	"fmt"
)

func main() {

	fmt.Println("Hello Pcpabeat created by newland")

	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

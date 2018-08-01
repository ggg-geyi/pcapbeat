package main

import (
	"os"

	"github.com/igaoliang/pcapbeat/cmd"
	"fmt"
)

func main() {

	fmt.Println("Hello Pcpabeat")

	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

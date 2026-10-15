package main

import (
	"fmt"
	"os"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/term"
)

func main() {
	_, err := zstd.NewWriter(nil)
	fmt.Println("airlock-demo: zstd ok:", err == nil, "| stdin is a terminal:", term.IsTerminal(int(os.Stdin.Fd())))
}

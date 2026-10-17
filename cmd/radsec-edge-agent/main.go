// radsec-edge-agent は、Docker Engine を操作する唯一の部品（設計概要 §10）。
// radsec-edge から unix ソケットで決まった操作だけを受け付け、テナントの radsecproxy のコンテナを固定のひな形で作る。
package main

import (
	"fmt"
	"os"
)

// version はビルド時に -ldflags "-X main.version=..." で埋め込む。
var version = "dev"

func main() {
	fmt.Fprintln(os.Stderr, "radsec-edge-agent", version, ": not implemented yet")
	os.Exit(1)
}

package main

import (
	_ "github.com/wader/fq/format/all"
	"github.com/wader/fq/pkg/cli"
	"github.com/wader/fq/pkg/interp"
)

const version = "0.2.0"

func main() {
	cli.Main(interp.DefaultRegistry, version)
}

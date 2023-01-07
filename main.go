package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

func main() {
	err := features.HaveProgramType(ebpf.LSM)
	if err != nil {
		log.Fatalf("error getting kernel version: %s", err)
	}
	fmt.Print("Supports LSM")
}

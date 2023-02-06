package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf test.bpf.c -- -I/usr/include/bpf -O2 -g

func main() {
	err := features.HaveProgramType(ebpf.LSM)
	if err != nil {
		log.Fatalf("error getting kernel version: %s", err)
	}
	fmt.Print("Supports LSM")

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kpbprm, err := link.AttachLSM(link.LSMOptions{objs.BprmStuff})
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kpbprm.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {

	}
}

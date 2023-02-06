package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf test.bpf.c -- -I/usr/include/bpf -O2 -g

type eventBPF struct {
	Comm [80]uint8
}

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

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	go func() {
		for {
			_, _ = exec.Command("sleep", "1").Output()
		}
	}()

	go func() {
		time.Sleep(20 * time.Second)
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
		os.Exit(0)
	}()

	var event eventBPF
	for {
		fmt.Printf("Waiting for event\t")
		record, err := rd.Read()
		fmt.Printf("Recieved event\t")
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		fmt.Printf("Exec %s \n", unix.ByteSliceToString(event.Comm[:]))
	}
}

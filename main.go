package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
)

func main() {
	var objs pkt_counterObjects
	if err := loadPkt_counterObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	nicName := "eth0"
	nic, err := net.InterfaceByName(nicName)
	if err != nil {
		log.Fatal(err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountPackets,
		Interface: nic.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer xdpLink.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	sigInt := make(chan os.Signal, 5)
	signal.Notify(sigInt, os.Interrupt)

	for {
		select {
		case <-ticker.C:
			var count, size []uint64
			if err := objs.PktCount.Lookup(uint32(0), &count); err != nil {
				log.Fatal(err)
			}
			if err = objs.PktSize.Lookup(uint32(0), &size); err != nil {
				log.Fatal(err)
			}
			for cpu := range count {
				log.Printf("cpu %d: Seen %d packets in %d bytes", cpu, count[cpu], size[cpu])
			}
		case <-sigInt:
			return
		}
	}
}

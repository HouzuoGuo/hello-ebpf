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
			var totalPacketCount, totalPacketLen []uint64
			var srcIP []byte
			var ipTrafficLen uint64

			if err := objs.PktCount.Lookup(uint32(0), &totalPacketCount); err != nil {
				log.Fatal(err)
			}
			if err = objs.PktSize.Lookup(uint32(0), &totalPacketLen); err != nil {
				log.Fatal(err)
			}
			srcTrafficIter := objs.SrcDataLen.Iterate()
			for srcTrafficIter.Next(&srcIP, &ipTrafficLen) {
				srcIPAddr := net.IPv4(srcIP[0], srcIP[1], srcIP[2], srcIP[3])
				log.Printf("source IP %s: %v bytes of traffic", srcIPAddr, ipTrafficLen)
			}
			for cpu := range totalPacketCount {
				log.Printf("cpu %d: Seen %d packets in %d bytes", cpu, totalPacketCount[cpu], totalPacketLen[cpu])
			}
		case <-sigInt:
			return
		}
	}
}

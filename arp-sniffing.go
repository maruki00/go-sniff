package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var device string
	flag.StringVar(&device, "iface", "eth0", "specify the device like wla0,eth0 ...")
	flag.Parse()

	snapshotLen := int32(1024)
	promiscuous := true
	timeout := pcap.BlockForever

	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//TODO: implement different Protocols

	err = handle.SetBPFFilter("tcp")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Listening for outgoing connections...")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			src, dst := netLayer.NetworkFlow().Endpoints()
			if ip := net.ParseIP(dst.String()); ip != nil {

				fmt.Printf("Outgoing IP: %s | From : %s\n", dst.String(), src.String())
			}
		}
	}
}

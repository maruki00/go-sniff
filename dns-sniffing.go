package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

	//TODO:  implmnt diff protocols.

	var filter = "udp and port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Listening for DNS queries on", device)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}

		dns, _ := dnsLayer.(*layers.DNS)
		for _, question := range dns.Questions {
			domain := string(question.Name)
			if !strings.HasSuffix(domain, "in-addr.arpa") {
				fmt.Println("Visited Domain:", domain)
			}
		}
	}
}

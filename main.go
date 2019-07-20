package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/moul/http2curl"
)

var (
	device  string
	port    int
	listDev bool
)

func init() {
	flag.StringVar(&device, "d", "", "device name")
	flag.IntVar(&port, "p", -1, "http server port")
	flag.BoolVar(&listDev, "l", false, "list network device")
	flag.Parse()

	if listDev {
		ListNetworkDevice()
		os.Exit(0)
	} else if len(device) == 0 {
		log.Fatalln("Missing device name")
	} else if port == -1 {
		log.Fatalln("Missing port")
	}
}

func main() {
	handle, err := pcap.OpenLive(device, 65535, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	bpf := fmt.Sprintf("tcp and port %d", port)
	err = handle.SetBPFFilter(bpf)
	if err != nil {
		log.Fatal(err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := src.Packets()

	// tcpassembly
	sp := tcpassembly.NewStreamPool(&streamFactory{})
	asm := tcpassembly.NewAssembler(sp)
	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-packets:
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
				packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Packet: Got unknown packet")
				continue
			}
			asm.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				packet.TransportLayer().(*layers.TCP),
				packet.Metadata().Timestamp,
			)
		case <-ticker:
			asm.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

type streamFactory struct{}

func (sf *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	reader := tcpreader.NewReaderStream()
	go Decode(netFlow, tcpFlow, &reader)
	return &reader
}

func Decode(netFlow, tcpFlow gopacket.Flow, r io.Reader) {
	buf := bufio.NewReader(r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			// http.ReadResponse(r, req)
			continue
		} else {
			req.ParseForm()
			command, err := http2curl.GetCurlCommand(req)
			if err == nil {
				log.Println(command.String() + "\n")
			} else {
				log.Printf("http to curl failed: %s", err)
			}
			req.Body.Close()
		}
	}
}

func ListNetworkDevice() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalln(err)
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					log.Println(iface.Name + " : " + ip4.String())
				}
			}
		}
	}
}

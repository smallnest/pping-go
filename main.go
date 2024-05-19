package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	liveInp   = flag.String("i", "", "interface")
	fname     = flag.String("r", "", "process capture file")
	filterOpt = flag.String("f", "", "pcap filter applied to packets.")
)

// "  -c|--count num     stop after capturing <num> packets\n"
// "\n"
// "  -s|--seconds num   stop after capturing for <num> seconds \n"
// "\n"

func main() {
	flag.DurationVar(&sumInt, "q", 10*time.Second, "interval to print summary reports to stderr")
	flag.BoolVar(&filtLocal, "l", false, "show RTTs through local host applications")
	flag.DurationVar(&timeToRun, "s", 0*time.Second, "stop after capturing for <num> seconds")
	flag.BoolVar(&machineReadable, "m", false, "machine readable output")
	flag.DurationVar(&tsvalMaxAge, "M", 10*time.Second, "max age of an unmatched tsval")
	flag.DurationVar(&flowMaxIdle, "F", 300*time.Second, "flows idle longer than <num> are deleted")
	flag.IntVar(&maxPackets, "c", 0, "stop after capturing <num> packets")

	flag.Parse()

	if *filterOpt != "" {
		filter += " and (" + *filterOpt + ")"
	}

	var snif *pcap.Handle
	var err error
	if *liveInp != "" {
		if filtLocal {
			localIP = localAddrOf(*liveInp)
			if localIP == "" {
				filtLocal = false
			}
		}
		inactive, _ := pcap.NewInactiveHandle(*liveInp)
		defer inactive.CleanUp()

		inactive.SetSnapLen(snapLen)

		snif, err = inactive.Activate()
		if err != nil {
			fmt.Printf("Couldn't open %s: %v\n", *fname, err)
			os.Exit(1)
		}
	} else if *fname != "" {
		snif, err = pcap.OpenOffline(*fname)
		if err != nil {
			fmt.Printf("Couldn't open %s: %v\n", *fname, err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("must set -i or -r\n")
		os.Exit(1)
	}
	defer snif.Close()

	if machineReadable {
		flushInt /= 10 // 每 100ms 输出一次
	}
	nextFlush = clockNow() + flushInt

	var nxtSum, nxtClean float64
	src := gopacket.NewPacketSource(snif, layers.LayerTypeEthernet)
	packets := src.Packets()
	for packet := range packets {
		processPacket(packet)

		if (timeToRun > 0 && capTm-startm >= float64(timeToRun)/float64(time.Second)) ||
			(maxPackets > 0 && pktCnt >= maxPackets) {
			printSummary()
			fmt.Printf("Captured %d packets in %.2f seconds\n", pktCnt, capTm-startm)
			break
		}
		if capTm >= nxtSum && sumInt > 0 {
			if nxtSum > 0 {
				printSummary()
				pktCnt, no_TS, uniDir, not_tcp, not_v4or6 = 0, 0, 0, 0, 0
			}
			nxtSum = capTm + float64(sumInt)/float64(time.Second)
		}
		if capTm >= nxtClean {
			cleanUp(capTm)
			nxtClean = capTm + float64(tsvalMaxAge)/float64(time.Second)
		}
	}
}

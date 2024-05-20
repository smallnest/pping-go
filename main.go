package main

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/pflag"
)

var (
	liveInp   = pflag.StringP("interface", "i", "", "interface name")
	fname     = pflag.StringP("read", "r", "", "pcap captured file")
	filterOpt = pflag.StringP("filter", "f", "", "pcap filter applied to packets")
)

func main() {
	pflag.DurationVarP(&sumInt, "sumInt", "q", 10*time.Second, "interval to print summary reports to stderr")
	pflag.BoolVarP(&filtLocal, "showLocal", "l", false, "show RTTs through local host applications")
	pflag.DurationVarP(&timeToRun, "seconds", "s", 0*time.Second, "stop after capturing for <num> seconds")
	pflag.IntVarP(&maxPackets, "count", "c", 0, "stop after capturing <num> packets")
	pflag.BoolVarP(&machineReadable, "machine", "m", false, "machine readable output")
	pflag.DurationVarP(&tsvalMaxAge, "tsvalMaxAge", "M", 10*time.Second, "max age of an unmatched tsval")
	pflag.DurationVarP(&flowMaxIdle, "flowMaxIdle", "F", 300*time.Second, "flows idle longer than <num> are deleted")

	pflag.Parse()

	if *filterOpt != "" {
		filter += " and (" + *filterOpt + ")"
	}

	// snif 是一个 pcap.Handle 类型的指针，用于处理 pcap 数据包捕获
	var snif *pcap.Handle
	var err error
	if *liveInp != "" {
		// 如果 filtLocal 为 true，我们获取本地地址
		if filtLocal {
			// localAddrOf 函数用于获取 *liveInp 的本地地址
			localIP = localAddrOf(*liveInp)
			// 如果没有获取到本地 IP，我们将 filtLocal 设置为 false
			if localIP == "" {
				filtLocal = false
			}
		}

		// 创建一个新的非活动 pcap 句柄
		inactive, _ := pcap.NewInactiveHandle(*liveInp)
		// 使用 defer 关键字确保在函数结束时清理非活动句柄
		defer inactive.CleanUp()

		// 设置捕获的数据包的最大长度
		inactive.SetSnapLen(snapLen)

		// 激活非活动句柄，返回一个活动句柄和可能的错误
		snif, err = inactive.Activate()
		// 如果在激活句柄时出现错误，我们打印错误并退出程序
		if err != nil {
			fmt.Printf("couldn't open %s: %v\n", *fname, err)
			os.Exit(1)
		}
	} else if *fname != "" {
		// 使用 pcap.OpenOffline 函数打开一个离线 pcap 文件，返回一个 pcap 句柄和可能的错误
		snif, err = pcap.OpenOffline(*fname)
		// 如果在打开文件时出现错误，我们打印错误并退出程序
		if err != nil {
			fmt.Printf("couldn't open %s: %v\n", *fname, err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("must set -i or -r\n")
		os.Exit(1)
	}
	defer snif.Close()

	// 使用 SetBPFFilter 方法设置 BPF 过滤器，过滤器的规则由变量 filter 定义
	snif.SetBPFFilter(filter)

	// 如果 machineReadable 为 true，我们将 flushInt 除以 10，这意味着每 100ms 就会有一次输出
	if machineReadable {
		flushInt /= 10 // Output every 100ms
	}

	// 设置下一次刷新的时间，即当前时间加上 flushInt
	nextFlush = clockNow() + flushInt

	// nxtSum 和 nxtClean 是两个浮点数，用于存储下一次的总和和清理值
	var nxtSum, nxtClean float64
	// 使用 gopacket.NewPacketSource 创建一个新的数据包源，该源从 snif 中读取数据包，并将其解码为以太网层
	src := gopacket.NewPacketSource(snif, layers.LayerTypeEthernet)
	// 使用 src.Packets() 获取一个数据包通道，我们可以从这个通道中读取数据包
	packets := src.Packets()
	for packet := range packets {
		processPacket(packet)

		// 检查是否已经达到了运行时间或数据包数量的限制
		// 如果运行时间大于0且从开始到现在的时间大于或等于运行时间
		// 或者如果最大数据包数量大于0且已捕获的数据包数量大于或等于最大数据包数量
		// 则打印摘要信息，并打印已捕获的数据包数量和捕获时间，然后跳出循环
		if (timeToRun > 0 && capTm-startm >= float64(timeToRun)/float64(time.Second)) ||
			(maxPackets > 0 && pktCnt >= maxPackets) {
			printSummary()
			fmt.Printf("captured %d packets in %.2f seconds\n", pktCnt, capTm-startm)
			break
		}

		// 如果当前捕获时间大于或等于下一次总结的时间，并且总结间隔大于0
		if capTm >= nxtSum && sumInt > 0 {
			// 如果下一次总结的时间大于0，打印总结信息，并将数据包计数、无时间戳计数、单向计数、非TCP计数和非v4或v6计数重置为0
			if nxtSum > 0 {
				printSummary()
				pktCnt, no_TS, uniDir, not_tcp, not_v4or6 = 0, 0, 0, 0, 0
			}
			// 设置下一次总结的时间，即当前捕获时间加上总结间隔
			nxtSum = capTm + float64(sumInt)/float64(time.Second)
		}

		// 如果当前捕获时间大于或等于下一次清理的时间
		if capTm >= nxtClean {
			// 调用 cleanUp 函数进行清理操作，参数为当前捕获时间
			cleanUp(capTm)
			// 设置下一次清理的时间，即当前捕获时间加上 tsvalMaxAge（最大时间戳值）除以一秒的时间
			nxtClean = capTm + float64(tsvalMaxAge)/float64(time.Second)
		}
	}
}

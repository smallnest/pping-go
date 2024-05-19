package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	snapLen         = 144               // 最大捕获字节数
	tsvalMaxAge     = 10 * time.Second  // 不匹配的 TSval 的最大年龄
	flowMaxIdle     = 300 * time.Second // 流空闲超过该时间后将被忘记
	sumInt          = 10 * time.Second  // 总结报告的打印间隔
	maxFlows        = 10000             // 最大流数量
	maxPackets      = 0                 // 最大捕获数据包数量 (0=无限制)
	timeToRun       = 0 * time.Second   // 捕获的持续时间 (0=无限制)
	machineReadable = false             // 机器可读或人类可读输出
	filtLocal       = true              // 忽略通过本地地址的流量
	filter          = "tcp"             // 默认 bpf 过滤器
	flushInt        = int64(1 << 20)    // stdout 刷新间隔 (~微秒)

)

type flowRec struct {
	flowname    string
	last_tm     float64
	min         float64 // 当前最小 capturepoint-to-source RTT
	bytesSnt    float64 // 通过 CP 向目标发送的字节数 (入站到 CP 或返回方向)
	lstBytesSnt float64 // 上次打印时 flow 的 bytesSnt 值
	bytesDep    float64 // 在 RTT 计算时设置为该流的 "forward" 或出站方向字节数
	revFlow     bool    // 是否已看到反向流
}

type tsInfo struct {
	t      float64 // TSval 数据包到达的壁钟时间
	fBytes float64 // 包括此数据包在内的流通过 CP 的总字节数
	dBytes float64 // 入站到 CP 的总字节数
}

var (
	flows     = make(map[string]*flowRec)
	tsTbl     = make(map[string]*tsInfo)
	localIP   string
	offTm     int64   = -1 // 第一个数据包捕获时间 (用于避免精度损失)
	capTm     float64      // 当前捕获时间 (秒)
	startm    float64      // 第一个有用数据包的时间 (秒)
	pktCnt    int
	not_tcp   int
	no_TS     int
	not_v4or6 int
	uniDir    int
	flowCnt   int
	nextFlush int64 // 下一次 stdout 刷新时间 (~微秒)
)

func fmtTimeDiff(dt float64) string {
	var SIprefix string
	if dt < 1e-3 {
		dt *= 1e6
		SIprefix = "u"
	} else if dt < 1 {
		dt *= 1e3
		SIprefix = "m"
	}
	var fmtStr string
	if dt < 10 {
		fmtStr = "%.2f%ss"
	} else if dt < 100 {
		fmtStr = "%.1f%ss"
	} else {
		fmtStr = " %.0f%ss"
	}

	return fmt.Sprintf(fmtStr, dt, SIprefix)
}

func clockNow() int64 {
	return time.Now().UnixNano() / 1000 // 微秒
}

func addTS(key string, ti *tsInfo) {
	if _, ok := tsTbl[key]; !ok {
		tsTbl[key] = ti
	}
}

func getTS(key string) *tsInfo {
	ti, ok := tsTbl[key]
	if ok {
		return ti
	}
	return nil
}

func getTSFromTCPOpts(tcp *layers.TCP) (uint32, uint32) {
	var tsval, tsecr uint32
	opts := tcp.Options
	for _, opt := range opts {
		if opt.OptionType == layers.TCPOptionKindTimestamps && opt.OptionLength == 10 { // Timestamp 选项长度为 10 字节
			tsval = binary.BigEndian.Uint32(opt.OptionData[0:4])
			tsecr = binary.BigEndian.Uint32(opt.OptionData[4:8])
			break
		}
	}
	return tsval, tsecr
}

func processPacket(pkt gopacket.Packet) {
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		not_tcp++
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	tsval, tsecr := getTSFromTCPOpts(tcp)
	if tsval == 0 || (tsecr == 0 && !tcp.SYN) {
		no_TS++
		return
	}

	netLayer := pkt.Layer(layers.LayerTypeIPv4)
	if netLayer == nil {
		netLayer = pkt.Layer(layers.LayerTypeIPv6)
		if netLayer == nil {
			not_v4or6++
			return
		}
	}

	var ipsStr, ipdStr string
	if ip, ok := netLayer.(*layers.IPv4); ok {
		ipsStr = ip.SrcIP.String()
		ipdStr = ip.DstIP.String()
	} else {
		ip := netLayer.(*layers.IPv6)
		ipsStr = ip.SrcIP.String()
		ipdStr = ip.DstIP.String()
	}

	srcStr := ipsStr + ":" + strconv.Itoa(int(tcp.SrcPort))
	dstStr := ipdStr + ":" + strconv.Itoa(int(tcp.DstPort))

	captureTime := pkt.Metadata().CaptureInfo.Timestamp

	if offTm < 0 {
		offTm = captureTime.Unix()
		startm = float64(captureTime.Nanosecond()) * 1e-9
		capTm = startm
		if sumInt > 0 {
			fmt.Printf("First packet at %s\n", captureTime.Format(time.UnixDate))
		}
	} else {
		capTm = float64(captureTime.Unix()-offTm) + float64(captureTime.Nanosecond())*1e-9
	}

	fstr := srcStr + "+" + dstStr
	fr, ok := flows[fstr]
	if !ok {
		if flowCnt >= maxFlows {
			return
		}
		fr = &flowRec{
			flowname: fstr,
			min:      1e30,
		}
		flows[fstr] = fr
		flowCnt++

		if _, ok := flows[dstStr+"+"+srcStr]; ok {
			flows[dstStr+"+"+srcStr].revFlow = true
			fr.revFlow = true
		}
	}
	fr.last_tm = capTm

	if !fr.revFlow {
		uniDir++
		return
	}

	arr_fwd := fr.bytesSnt + float64(pkt.Metadata().Length)
	fr.bytesSnt = arr_fwd
	if !filtLocal || localIP != ipdStr {
		addTS(fstr+"+"+strconv.FormatUint(uint64(tsval), 10), &tsInfo{capTm, arr_fwd, fr.bytesDep})
	}

	ti := getTS(dstStr + "+" + srcStr + "+" + strconv.FormatUint(uint64(tsecr), 10))
	if ti != nil && ti.t > 0.0 {
		// 这是返回的 "pping" 数据包 -- 处理源数据包
		t := ti.t
		rtt := capTm - t
		if fr.min > rtt {
			fr.min = rtt // 跟踪最小值
		}
		fBytes := ti.fBytes
		dBytes := ti.dBytes
		pBytes := arr_fwd - fr.lstBytesSnt
		fr.lstBytesSnt = arr_fwd
		flows[dstStr+"+"+srcStr].bytesDep = fBytes

		if machineReadable {
			fmt.Printf("%d.%06d %.6f %.6f %.0f %.0f %.0f", int64(capTm+float64(offTm)), int((capTm-float64(int64(capTm)))*1e6), rtt, fr.min, fBytes, dBytes, pBytes)
		} else {
			fmt.Printf("%s %s %s %s\n", captureTime.Format("15:04:05"), fmtTimeDiff(rtt), fmtTimeDiff(fr.min), fstr)
		}
		now := clockNow()
		if now-nextFlush >= 0 {
			nextFlush = now + flushInt
			// fmt.Print(os.Stdout, nil)
		}
		ti.t = -t // 将条目标记为已使用,避免再次保存这个 TSval
	}
	pktCnt++
}

func cleanUp(n float64) {
	// 如果 TSval 的时间超过 tsvalMaxAge,则删除条目
	for k, ti := range tsTbl {
		if capTm-math.Abs(ti.t) > float64(tsvalMaxAge)/float64(time.Second) {
			delete(tsTbl, k)
		}
	}
	for k, fr := range flows {
		if n-fr.last_tm > float64(flowMaxIdle)/float64(time.Second) {
			delete(flows, k)
			flowCnt--
		}
	}
}

func localAddrOf(ifname string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Name != ifname {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return ""
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}

	return ""
}

func printSummary() {
	fmt.Printf("%d flows, %d packets", flowCnt, pktCnt)
	if no_TS > 0 {
		fmt.Printf(", %d no TS opt", no_TS)
	}
	if uniDir > 0 {
		fmt.Printf(", %d uni-directional", uniDir)
	}
	if not_tcp > 0 {
		fmt.Printf(", %d not TCP", not_tcp)
	}
	if not_v4or6 > 0 {
		fmt.Printf(", %d not v4 or v6", not_v4or6)
	}
	fmt.Println()
}

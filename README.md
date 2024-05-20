# pping-go

使用Go语言实现[pping](https://github.com/pollere/pping).

`pping` (passive ping) 是一个 Linux/macOS/BSD 命令行工具,通过被动监控活跃连接来测量网络延迟。

与 `ping` 不同, `pping` 不会主动发送探测包来计算 RTT(往返时间),而是监控正常TCP应用流量所经历的每个数据包的 RTT。

与只能在发送端测量 RTT 的传输状态监控工具(如 `ss`)不同, `pping` 可以在连接路径的任何位置(例如 OpenWrt 家用边界路由器)测量 RTT,无论是发送端、接收端或中间节点。

## 安装

```sh
go install github.com/smallnest/pping-go@latest
```

## 运行

```sh
[root@vps3 pping]# ./pping -i eth0 -l
first packet at Mon May 20 12:03:57 CST 2024
12:03:58  227ms  227ms 111.108.111.135:55168+74.48.173.243:22
12:03:58  225ms  225ms 111.108.111.135:55168+74.48.173.243:22
12:03:58  225ms  225ms 111.108.111.135:55168+74.48.173.243:22
12:03:58  225ms  225ms 111.108.111.135:55168+74.48.173.243:22
12:03:58  225ms  225ms 111.108.111.135:55168+74.48.173.243:22
12:03:59  223ms  223ms 111.108.111.135:55168+74.48.173.243:22
12:03:59  224ms  223ms 111.108.111.135:55168+74.48.173.243:22
12:03:59  224ms  223ms 111.108.111.135:55168+74.48.173.243:22
12:03:59  225ms  223ms 111.108.111.135:55168+74.48.173.243:22
```

## TCP 时间戳选项

pping需要监控的TCP包含时间戳选项，你可以在服务器开启时间戳选项：

```sh
# sysctl -w net.ipv4.tcp_timestamps=1
net.ipv4.tcp_timestamps = 1
```

查看是否开启:
```sh
# sysctl net.ipv4.tcp_timestamps
net.ipv4.tcp_timestamps = 1
```

或者
```sh
cat /proc/sys/net/ipv4/tcp_timestamps
```
package kone

func configureDNSListenerFamilies(d *Dns) {
	d.server.Net, d.tcpServer.Net = "udp4", "tcp4"
}

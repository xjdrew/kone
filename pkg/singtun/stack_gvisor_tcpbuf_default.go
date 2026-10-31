// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build with_gvisor && !ios

package tun

import "github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"

const (
	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultReceiveBufferSize
	tcpRXBufMaxSize = 8 << 20 // 8MiB

	tcpTXBufMinSize = tcp.MinBufferSize
	tcpTXBufDefSize = tcp.DefaultSendBufferSize
	tcpTXBufMaxSize = 6 << 20 // 6MiB
)

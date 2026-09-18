package main

import (
	"encoding/binary"
	"errors"
)

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	extensionTypeServerName  = 0x0000
	sniTypeHostName          = 0x00
)

var (
	// errNeedMoreData 表示现有字节还不足以判定，调用方应继续读取。
	errNeedMoreData = errors.New("need more data")
	// errNotClientHello 表示这些字节不是可解析的 ClientHello，不必再读。
	errNotClientHello = errors.New("not a TLS client hello")
)

// sniFromTLSRecords 从连接首部提取 ClientHello 里的 SNI，作用等价于 Caddy
// layer4 的 `tls sni` matcher。
//
// 这里刻意不复用 xray-core 的 common/protocol/tls.SniffTLS：那会把 xray-core
// 整棵依赖树拖进这个只有几 MiB 的转发进程。解析本身是纯字节扫描，只依赖
// encoding/binary。
//
// 返回 errNeedMoreData 表示缓冲区还不够，调用方应再读一些；返回
// errNotClientHello 表示不是 ClientHello，不必再读。SNI 为空但 err 为 nil 是
// 合法结果——那是一个没带 server_name 扩展的 ClientHello，调用方按「无 SNI」
// 处理，与解析失败一样退回默认路由。
func sniFromTLSRecords(record []byte) (string, error) {
	// TLS record: type(1) version(2) length(2)
	if len(record) < 5 {
		return "", errNeedMoreData
	}
	if record[0] != recordTypeHandshake {
		return "", errNotClientHello
	}
	// 主版本必须是 3（SSLv3 与 TLS 各版本都是）。不细分小版本：TLS 1.3 的
	// legacy_version 固定写成 0x0303，但部分客户端在 1.3 下仍发 0x0301。
	if record[1] != 3 {
		return "", errNotClientHello
	}
	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+recordLen {
		return "", errNeedMoreData
	}

	// handshake: type(1) length(3)
	handshake := record[5 : 5+recordLen]
	if len(handshake) < 4 {
		return "", errNotClientHello
	}
	if handshake[0] != handshakeTypeClientHello {
		return "", errNotClientHello
	}
	bodyLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+bodyLen {
		// 整个 ClientHello 装不进这一个 record，说明它跨了 record。真实客户端
		// 不会这么发（ClientHello 远小于 record 上限），放弃而不是无限等待。
		return "", errNotClientHello
	}

	return sniFromClientHelloBody(handshake[4 : 4+bodyLen])
}

func sniFromClientHelloBody(b []byte) (string, error) {
	// legacy_version(2) + random(32)
	b, ok := skipBytes(b, 34)
	if !ok {
		return "", errNotClientHello
	}

	// session_id: length(1) + bytes
	b, ok = skipLengthPrefixedU8(b)
	if !ok {
		return "", errNotClientHello
	}

	// cipher_suites: length(2) + bytes
	b, ok = skipLengthPrefixedU16(b)
	if !ok {
		return "", errNotClientHello
	}

	// compression_methods: length(1) + bytes
	b, ok = skipLengthPrefixedU8(b)
	if !ok {
		return "", errNotClientHello
	}

	// 到这里 ClientHello 的固定部分已经结束。没有 extensions 段就说明客户端
	// 根本没发 SNI，属于合法结果而不是错误。
	if len(b) < 2 {
		return "", nil
	}
	extensionsLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if len(b) < extensionsLen {
		return "", errNotClientHello
	}
	return sniFromExtensions(b[:extensionsLen])
}

func sniFromExtensions(extensions []byte) (string, error) {
	for len(extensions) > 0 {
		// extension: type(2) length(2) data
		if len(extensions) < 4 {
			return "", errNotClientHello
		}
		extType := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			return "", errNotClientHello
		}
		data := extensions[:extLen]
		extensions = extensions[extLen:]

		if extType == extensionTypeServerName {
			return sniFromServerNameExtension(data)
		}
	}
	return "", nil
}

func sniFromServerNameExtension(data []byte) (string, error) {
	// ServerNameList: length(2) + entries
	if len(data) < 2 {
		return "", errNotClientHello
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	list := data[2:]
	if len(list) < listLen {
		return "", errNotClientHello
	}
	list = list[:listLen]

	for len(list) > 0 {
		// entry: type(1) length(2) name
		if len(list) < 3 {
			return "", errNotClientHello
		}
		nameType := list[0]
		nameLen := int(binary.BigEndian.Uint16(list[1:3]))
		list = list[3:]
		if len(list) < nameLen {
			return "", errNotClientHello
		}
		name := list[:nameLen]
		list = list[nameLen:]

		if nameType == sniTypeHostName {
			return string(name), nil
		}
	}
	return "", nil
}

func skipBytes(b []byte, n int) ([]byte, bool) {
	if n < 0 || len(b) < n {
		return nil, false
	}
	return b[n:], true
}

func skipLengthPrefixedU8(b []byte) ([]byte, bool) {
	if len(b) < 1 {
		return nil, false
	}
	return skipBytes(b[1:], int(b[0]))
}

func skipLengthPrefixedU16(b []byte) ([]byte, bool) {
	if len(b) < 2 {
		return nil, false
	}
	return skipBytes(b[2:], int(binary.BigEndian.Uint16(b[:2])))
}

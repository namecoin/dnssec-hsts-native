package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"

	"github.com/miekg/dns"

	"github.com/namecoin/qlib"
)

type NativeRequestMessage struct {
	Hostname string `json:"hostname"`
	Host string     `json:"host"`
	Port uint16     `json:"port"`
}

type NativeResponseMessage struct {
	Hostname string `json:"hostname"`
	Host string     `json:"host"`
	Port uint16     `json:"port"`
	HasTLSA bool    `json:"hasTLSA"`
	Ok bool         `json:"ok"`
}

func main() {
	for {
		s := bufio.NewReader(os.Stdin)
		length := make([]byte, 4)
		s.Read(length)
		lengthNum := nativeReadMessageLength(length)
		content := make([]byte, lengthNum)
		s.Read(content)
		nativeRequest := decodeNativeMessage(content)

		var hasTLSA bool
		var ok bool

		qparams := qlib.DefaultParams()
		qparams.Ad = true
		qparams.Fallback = true
		qparams.Tcp = true // Workaround for https://github.com/miekg/exdns/issues/19

		result, err := qparams.Do([]string{"TLSA", "_443._tcp." + nativeRequest.Hostname})
		if err != nil {
			// A DNS error occurred.  This could indicate a MITM attack;
			// upgrade to TLS and report an error.
			hasTLSA = true
			ok = false
		} else if result.ResponseMsg == nil {
			// A DNS error occurred.  This could indicate a MITM attack;
			// upgrade to TLS and report an error.
			hasTLSA = true
			ok = false
		} else if result.ResponseMsg.MsgHdr.Rcode != dns.RcodeSuccess && result.ResponseMsg.MsgHdr.Rcode != dns.RcodeNameError {
			// A DNS error occurred.  This could indicate a MITM attack;
			// upgrade to TLS and report an error.
			hasTLSA = true
			ok = false
		} else if result.ResponseMsg.MsgHdr.AuthenticatedData == false && result.ResponseMsg.MsgHdr.Authoritative == false {
			// AD and AA are both false.  That means the domain
			// doesn't use DNSSEC.
			hasTLSA = false
			ok = true
		} else if len(result.ResponseMsg.Answer) == 0 || result.ResponseMsg.MsgHdr.Rcode == dns.RcodeNameError {
			// AD or AA is true but no TLSA records exist.  That
			// means the domain uses DNSSEC but doesn't use DANE.
			hasTLSA = false
			ok = true
		} else {
			// AD or AA is true and TLSA records were found.  That
			// means the domain uses DNSSEC and DANE.  Upgrade to
			// TLS.
			hasTLSA = true
			ok = true
		}

		nativeResponse := NativeResponseMessage {
			Hostname: nativeRequest.Hostname,
			Host:     nativeRequest.Host,
			Port:     nativeRequest.Port,
			HasTLSA:  hasTLSA,
			Ok:       ok,
		}

		sendNative(&nativeResponse)
	}
}

func sendNative(msg *NativeResponseMessage) {
	byteMsg := nativeDataToBytes(msg)
	var msgBuf bytes.Buffer
	nativeWriteMessageLength(byteMsg)
	msgBuf.Write(byteMsg)
	msgBuf.WriteTo(os.Stdout)
}

func decodeNativeMessage(msg []byte) *NativeRequestMessage {
	var aMessage NativeRequestMessage
	json.Unmarshal(msg, &aMessage)
	return &aMessage
}

func nativeDataToBytes(msg *NativeResponseMessage) []byte {
	byteMsg, _ := json.Marshal(*msg)
	return byteMsg
}

func nativeWriteMessageLength(msg []byte) {
	binary.Write(os.Stdout, binary.LittleEndian, uint32(len(msg)))
}

func nativeReadMessageLength(msg []byte) int {
	var length uint32
	buf := bytes.NewBuffer(msg)
	binary.Read(buf, binary.LittleEndian, &length)
	return int(length)
}

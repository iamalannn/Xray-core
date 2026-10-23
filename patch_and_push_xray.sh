#!/usr/bin/env bash
set -e

cd /workspaces/Xray-core

cat << 'GOEOF' > transport/internet/tls/mutator.go
package tls

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/errors"
)

type CarrierType int

const (
	CarrierGreaseRandom CarrierType = iota
	CarrierPadding0015
	CarrierLegacyNPN
)

type PreambleType int

const (
	PreambleNone PreambleType = iota
	PreambleZeroRecord
	PreambleAlertWarn
	PreambleCCS
)

type SplitBoundary int

const (
	SplitNone SplitBoundary = iota
	SplitAfterCiphers
	SplitBeforeSNI
)

type DetachMode int

const (
	DetachNone DetachMode = iota
	DetachSplit5
	DetachOOB
)

type MutationOptions struct {
	Enabled         bool
	DecoySNI        string
	Carrier         CarrierType
	TargetOffset    int
	HighEntropy     bool
	RepeatCount     int
	RawGreaseInject bool
	Preamble        PreambleType
	Split           SplitBoundary
	OuterVersion    uint16
	Detach          DetachMode
	OOBByte         byte
	JitterMinMs     int
	JitterMaxMs     int
}

func pickCarrierID(c CarrierType, usedGrease map[uint16]bool) uint16 {
	switch c {
	case CarrierPadding0015:
		return 0x0015
	case CarrierLegacyNPN:
		return 0x3374
	default:
		candidates := []uint16{0xdada, 0xcaca, 0xbaba, 0x9a9a, 0x7a7a, 0x5a5a, 0x3a3a, 0x2a2a}
		for _, id := range candidates {
			if !usedGrease[id] {
				return id
			}
		}
		return 0xdada
	}
}

func ParseSNIMutationTag(rawSNI string) (cleanSNI string, opts MutationOptions) {
	idx := strings.Index(rawSNI, "#mut=")
	if idx == -1 {
		return strings.ToLower(strings.TrimSpace(rawSNI)), opts
	}

	cleanSNI = strings.ToLower(strings.TrimSpace(rawSNI[:idx]))
	tagPart := rawSNI[idx+5:]

	opts.TargetOffset = 600
	opts.RepeatCount = 1
	opts.OOBByte = 0x78
	opts.JitterMinMs = 20
	opts.JitterMaxMs = 30

	for _, token := range strings.Split(tagPart, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		switch {
		case strings.HasPrefix(token, "decoy:") || strings.HasPrefix(token, "grease:"):
			val := strings.TrimPrefix(strings.TrimPrefix(token, "decoy:"), "grease:")
			if val != "" && val != "none" {
				opts.DecoySNI = strings.ToLower(strings.TrimSpace(val))
				opts.Enabled = true
			}
		case strings.HasPrefix(token, "carrier:"):
			switch strings.TrimPrefix(token, "carrier:") {
			case "pad0015":
				opts.Carrier = CarrierPadding0015
			case "npn3374":
				opts.Carrier = CarrierLegacyNPN
			default:
				opts.Carrier = CarrierGreaseRandom
			}
			opts.Enabled = true
		case strings.HasPrefix(token, "offset:"):
			if v, err := strconv.Atoi(strings.TrimPrefix(token, "offset:")); err == nil && v >= 0 && v <= 2000 {
				opts.TargetOffset = v
				opts.Enabled = true
			}
		case strings.HasPrefix(token, "entropy:"):
			opts.HighEntropy = strings.TrimPrefix(token, "entropy:") == "high"
			opts.Enabled = true
		case strings.HasPrefix(token, "repeat:"):
			if v, err := strconv.Atoi(strings.TrimPrefix(token, "repeat:")); err == nil && v >= 1 && v <= 5 {
				opts.RepeatCount = v
				opts.Enabled = true
			}
		case strings.HasPrefix(token, "preamble:"):
			switch strings.TrimPrefix(token, "preamble:") {
			case "zero":
				opts.Preamble = PreambleZeroRecord
			case "alert":
				opts.Preamble = PreambleAlertWarn
			case "ccs":
				opts.Preamble = PreambleCCS
			case "none":
				opts.Preamble = PreambleNone
			}
			opts.Enabled = true
		case strings.HasPrefix(token, "split:"):
			switch strings.TrimPrefix(token, "split:") {
			case "cipher":
				opts.Split = SplitAfterCiphers
			case "sni":
				opts.Split = SplitBeforeSNI
			case "none":
				opts.Split = SplitNone
			}
			opts.Enabled = true
		case strings.HasPrefix(token, "ver:"):
			switch strings.TrimPrefix(token, "ver:") {
			case "0302":
				opts.OuterVersion = 0x0302
			case "0300":
				opts.OuterVersion = 0x0300
			case "none", "0301":
				opts.OuterVersion = 0x0301
			}
			opts.Enabled = true
		case token == "ver02":
			opts.OuterVersion = 0x0302
			opts.Enabled = true
		case strings.HasPrefix(token, "oob:"):
			switch strings.TrimPrefix(token, "oob:") {
			case "split5":
				opts.Detach = DetachSplit5
			case "oob":
				opts.Detach = DetachOOB
			case "none":
				opts.Detach = DetachNone
			}
			opts.Enabled = true
		case token == "oob":
			opts.Detach = DetachOOB
			opts.Enabled = true
		case strings.HasPrefix(token, "jitter:"):
			parts := strings.Split(strings.TrimPrefix(token, "jitter:"), "-")
			if len(parts) == 2 {
				minV, err1 := strconv.Atoi(parts[0])
				maxV, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && minV >= 0 && maxV >= minV && maxV <= 500 {
					opts.JitterMinMs = minV
					opts.JitterMaxMs = maxV
					opts.Enabled = true
				}
			}
		}
	}
	return cleanSNI, opts
}

func BuildPhantomSNIPayload(opts MutationOptions) []byte {
	domainBytes := []byte(opts.DecoySNI)
	domainLen := len(domainBytes)
	repeat := opts.RepeatCount
	if repeat < 1 {
		repeat = 1
	}

	sniListLen := 1 + 2 + domainLen
	sniExtLen := 2 + sniListLen

	buf := bytes.NewBuffer(make([]byte, 0, opts.TargetOffset+128))
	for i := 0; i < repeat; i++ {
		_ = binary.Write(buf, binary.BigEndian, uint16(0x0000))
		_ = binary.Write(buf, binary.BigEndian, uint16(sniExtLen))
		_ = binary.Write(buf, binary.BigEndian, uint16(sniListLen))
		buf.WriteByte(0x00)
		_ = binary.Write(buf, binary.BigEndian, uint16(domainLen))
		buf.Write(domainBytes)
	}

	padLen := opts.TargetOffset - buf.Len()
	if padLen > 0 {
		pad := make([]byte, padLen)
		if opts.HighEntropy {
			_, _ = rand.Read(pad)
		}
		buf.Write(pad)
	}
	return buf.Bytes()
}

func ApplyUTLSGreasePhantomSNI(uConn *utls.UConn, opts MutationOptions) error {
	if !opts.Enabled || opts.DecoySNI == "" {
		return nil
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		return err
	}

	usedGrease := make(map[uint16]bool)
	for _, ext := range uConn.Extensions {
		if g, ok := ext.(*utls.UtlsGREASEExtension); ok {
			usedGrease[g.Value] = true
		}
	}

	carrierID := pickCarrierID(opts.Carrier, usedGrease)
	phantomPayload := BuildPhantomSNIPayload(opts)
	phantomExt := &utls.GenericExtension{
		Id:   carrierID,
		Data: phantomPayload,
	}

	var sniExt utls.TLSExtension
	var pskExt utls.TLSExtension
	filtered := make([]utls.TLSExtension, 0, len(uConn.Extensions)+1)

	for _, ext := range uConn.Extensions {
		switch e := ext.(type) {
		case *utls.SNIExtension:
			e.ServerName = strings.ToLower(strings.TrimSpace(e.ServerName))
			sniExt = e
		case *utls.UtlsPaddingExtension:
			continue
		case *utls.UtlsPreSharedKeyExtension:
			pskExt = e
		default:
			if _, isPSK := ext.(utls.PreSharedKeyExtension); isPSK {
				pskExt = ext
			} else {
				filtered = append(filtered, ext)
			}
		}
	}

	result := make([]utls.TLSExtension, 0, len(filtered)+3)
	result = append(result, phantomExt)
	result = append(result, filtered...)
	if sniExt != nil {
		result = append(result, sniExt)
	}
	if pskExt != nil {
		result = append(result, pskExt)
	}

	uConn.Extensions = result
	return uConn.BuildHandshakeState()
}

type CustomConnWrapper struct {
	net.Conn
	opts      MutationOptions
	firstOnce sync.Once
}

func NewCustomConnWrapper(conn net.Conn, opts MutationOptions) net.Conn {
	if !opts.Enabled {
		return conn
	}
	return &CustomConnWrapper{
		Conn: conn,
		opts: opts,
	}
}

func (w *CustomConnWrapper) sleepJitter() {
	if w.opts.JitterMaxMs <= 0 {
		return
	}
	d := w.opts.JitterMinMs
	if w.opts.JitterMaxMs > w.opts.JitterMinMs {
		d += mrand.Intn(w.opts.JitterMaxMs - w.opts.JitterMinMs + 1)
	}
	if d > 0 {
		time.Sleep(time.Duration(d) * time.Millisecond)
	}
}

func (w *CustomConnWrapper) Write(b []byte) (int, error) {
	isFirst := false
	w.firstOnce.Do(func() {
		isFirst = true
	})

	if !isFirst || len(b) < 43 || b[0] != 0x16 || b[5] != 0x01 {
		return w.Conn.Write(b)
	}

	origLen := len(b)
	packet := make([]byte, len(b))
	copy(packet, b)

	recLen := int(binary.BigEndian.Uint16(packet[3:5]))
	if len(packet) != 5+recLen {
		return w.Conn.Write(b)
	}

	if w.opts.RawGreaseInject && w.opts.DecoySNI != "" {
		if mutatedPkt, err := injectGreasePhantomSNIRaw(packet, w.opts); err == nil {
			packet = mutatedPkt
		}
	}

	outerVer := binary.BigEndian.Uint16(packet[1:3])
	if w.opts.OuterVersion != 0 {
		outerVer = w.opts.OuterVersion
		packet[1] = byte(outerVer >> 8)
		packet[2] = byte(outerVer)
	}

	w.setNoDelay(true)

	if w.opts.Preamble != PreambleNone {
		var preamble []byte
		switch w.opts.Preamble {
		case PreambleZeroRecord:
			preamble = []byte{0x16, byte(outerVer >> 8), byte(outerVer), 0x00, 0x00}
		case PreambleAlertWarn:
			preamble = []byte{0x15, byte(outerVer >> 8), byte(outerVer), 0x00, 0x02, 0x01, 0x00}
		case PreambleCCS:
			preamble = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
		}
		if len(preamble) > 0 {
			if _, err := w.Conn.Write(preamble); err != nil {
				return 0, err
			}
			w.sleepJitter()
		}
	}

	if w.opts.Split != SplitNone {
		if splitPkts, ok := splitTLSRecordStructurally(packet, w.opts.Split, outerVer); ok {
			if err := w.sendFirstRecord(splitPkts[0]); err != nil {
				return 0, err
			}
			w.sleepJitter()
			if _, err := w.Conn.Write(splitPkts[1]); err != nil {
				return 0, err
			}
			return origLen, nil
		}
	}

	if err := w.sendFirstRecord(packet); err != nil {
		return 0, err
	}

	return origLen, nil
}

func (w *CustomConnWrapper) sendFirstRecord(record []byte) error {
	switch w.opts.Detach {
	case DetachSplit5:
		if _, err := w.Conn.Write(record[:5]); err != nil {
			return err
		}
		w.sleepJitter()
		_, err := w.Conn.Write(record[5:])
		return err
	case DetachOOB:
		return w.writeWithDetachedOOB(record)
	default:
		_, err := w.Conn.Write(record)
		return err
	}
}

func (w *CustomConnWrapper) writeWithDetachedOOB(packet []byte) error {
	rawConn, err := extractSyscallConn(w.Conn)
	if err != nil || rawConn == nil {
		if _, err := w.Conn.Write(packet[:5]); err != nil {
			return err
		}
		w.sleepJitter()
		_, err = w.Conn.Write(packet[5:])
		return err
	}

	headerWithOOB := make([]byte, 6)
	copy(headerWithOOB[:5], packet[:5])
	headerWithOOB[5] = w.opts.OOBByte

	var sendErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		sendErr = syscall.Sendto(int(fd), headerWithOOB, syscall.MSG_OOB, nil)
	})

	if ctrlErr != nil || sendErr != nil {
		if _, err := w.Conn.Write(packet[:5]); err != nil {
			return err
		}
	}

	w.sleepJitter()
	_, err = w.Conn.Write(packet[5:])
	return err
}

// splitTLSRecordStructurally پیمایش دقیق TLV اکستنشن‌ها برای یافتن آخرین اکستنشن 0x0000 (SNI اصلی)
func splitTLSRecordStructurally(record []byte, boundary SplitBoundary, outerVer uint16) ([2][]byte, bool) {
	var out [2][]byte
	if len(record) < 44 || record[0] != 0x16 {
		return out, false
	}

	offset := 43
	if offset >= len(record) {
		return out, false
	}
	sessLen := int(record[offset])
	offset += 1 + sessLen
	if offset+2 > len(record) {
		return out, false
	}
	cipherLen := int(binary.BigEndian.Uint16(record[offset : offset+2]))
	offset += 2 + cipherLen
	if offset+1 > len(record) {
		return out, false
	}
	compLen := int(record[offset])
	afterCiphersOffset := offset + 1 + compLen

	splitPoint := 0
	if boundary == SplitAfterCiphers {
		splitPoint = afterCiphersOffset
	} else if boundary == SplitBeforeSNI {
		if afterCiphersOffset+2 > len(record) {
			return out, false
		}
		extTotalLen := int(binary.BigEndian.Uint16(record[afterCiphersOffset : afterCiphersOffset+2]))
		pos := afterCiphersOffset + 2
		end := pos + extTotalLen
		for pos+4 <= end && pos+4 <= len(record) {
			extType := binary.BigEndian.Uint16(record[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(record[pos+2 : pos+4]))
			if extType == 0x0000 {
				splitPoint = pos
			}
			pos += 4 + extLen
		}
	}

	if splitPoint <= 5 || splitPoint >= len(record) {
		return out, false
	}

	hsPart1 := record[5:splitPoint]
	hsPart2 := record[splitPoint:]

	rec1 := make([]byte, 5+len(hsPart1))
	rec1[0] = 0x16
	binary.BigEndian.PutUint16(rec1[1:3], outerVer)
	binary.BigEndian.PutUint16(rec1[3:5], uint16(len(hsPart1)))
	copy(rec1[5:], hsPart1)

	rec2 := make([]byte, 5+len(hsPart2))
	rec2[0] = 0x16
	binary.BigEndian.PutUint16(rec2[1:3], outerVer)
	binary.BigEndian.PutUint16(rec2[3:5], uint16(len(hsPart2)))
	copy(rec2[5:], hsPart2)

	out[0] = rec1
	out[1] = rec2
	return out, true
}

func injectGreasePhantomSNIRaw(record []byte, opts MutationOptions) ([]byte, error) {
	if len(record) < 44 || record[0] != 0x16 || record[5] != 0x01 {
		return nil, errors.New("invalid TLS ClientHello")
	}
	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+recordLen {
		return nil, errors.New("incomplete TLS record")
	}

	offset := 43
	sessionIDLen := int(record[offset])
	offset += 1 + sessionIDLen
	cipherSuitesLen := int(binary.BigEndian.Uint16(record[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	compMethodsLen := int(record[offset])
	offset += 1 + compMethodsLen

	extTotalLenOffset := offset
	extTotalLen := int(binary.BigEndian.Uint16(record[extTotalLenOffset : extTotalLenOffset+2]))
	extStartOffset := extTotalLenOffset + 2

	carrierID := pickCarrierID(opts.Carrier, nil)
	phantomPayload := BuildPhantomSNIPayload(opts)
	greaseExt := make([]byte, 4+len(phantomPayload))
	binary.BigEndian.PutUint16(greaseExt[0:2], carrierID)
	binary.BigEndian.PutUint16(greaseExt[2:4], uint16(len(phantomPayload)))
	copy(greaseExt[4:], phantomPayload)

	extBytes := record[extStartOffset : extStartOffset+extTotalLen]
	var sniBlock, pskBlock []byte
	var otherExts bytes.Buffer

	pos := 0
	for pos+4 <= len(extBytes) {
		extType := binary.BigEndian.Uint16(extBytes[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(extBytes[pos+2 : pos+4]))
		if pos+4+extLen > len(extBytes) {
			break
		}
		currExt := extBytes[pos : pos+4+extLen]
		switch extType {
		case 0x0000:
			sniBlock = currExt
		case 0x0029:
			pskBlock = currExt
		default:
			otherExts.Write(currExt)
		}
		pos += 4 + extLen
	}

	var newExtsBuf bytes.Buffer
	newExtsBuf.Write(greaseExt)
	newExtsBuf.Write(otherExts.Bytes())
	if sniBlock != nil {
		newExtsBuf.Write(sniBlock)
	}
	if pskBlock != nil {
		newExtsBuf.Write(pskBlock)
	}

	newExtsBytes := newExtsBuf.Bytes()
	addedLen := len(newExtsBytes) - extTotalLen
	newRecordLen := recordLen + addedLen
	if newRecordLen > 0xFFFF {
		return nil, errors.New("record overflow")
	}

	out := make([]byte, 0, extStartOffset+len(newExtsBytes))
	out = append(out, record[:extStartOffset]...)
	out = append(out, newExtsBytes...)

	binary.BigEndian.PutUint16(out[3:5], uint16(newRecordLen))
	oldHsLen := (int(out[6]) << 16) | (int(out[7]) << 8) | int(out[8])
	newHsLen := oldHsLen + addedLen
	out[6] = byte(newHsLen >> 16)
	out[7] = byte(newHsLen >> 8)
	out[8] = byte(newHsLen)
	binary.BigEndian.PutUint16(out[extTotalLenOffset:extTotalLenOffset+2], uint16(len(newExtsBytes)))

	return out, nil
}

func extractSyscallConn(c net.Conn) (syscall.RawConn, error) {
	type syscallConnGetter interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if sc, ok := c.(syscallConnGetter); ok {
		return sc.SyscallConn()
	}
	if tcpConn, ok := c.(*net.TCPConn); ok {
		return tcpConn.SyscallConn()
	}
	return nil, errors.New("no SyscallConn")
}

func (w *CustomConnWrapper) setNoDelay(noDelay bool) {
	if tcpConn, ok := w.Conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(noDelay)
	}
}
GOEOF

go mod tidy
go test -v ./transport/internet/tls

git add .
git commit -m "fix(tls): structured TLV SNI split, remove Chrome padding conflict, lowercase SNI" || true
git push origin HEAD

echo "========================================================"
echo "✅ Xray-core Pushed! COPY THIS COMMIT HASH FOR STEP 2:"
git rev-parse HEAD
echo "========================================================"

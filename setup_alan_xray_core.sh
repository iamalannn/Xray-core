#!/usr/bin/env bash
set -e

echo "========================================================"
echo "   ⚡ AlanNG - Xray-core Anti-DPI Engine Setup"
echo "========================================================"

# تشخیص خودکار مسیر ریشه xray-core
if [ -f "go.mod" ] && [ -d "transport/internet/tls" ]; then
    XRAY_ROOT="$(pwd)"
elif [ -d "xray-core/transport/internet/tls" ]; then
    XRAY_ROOT="$(pwd)/xray-core"
else
    echo "❌ Error: Please run this script inside the xray-core repository root."
    exit 1
fi

echo "📂 Detected xray-core root at: ${XRAY_ROOT}"
cd "${XRAY_ROOT}"

# ---------------------------------------------------------
# گام ۱: حذف echPublicName (حفظ tcpfrag:// و echDecoyDomain)
# ---------------------------------------------------------
echo "[1/4] Cleaning up any legacy echPublicName modifications..."
python3 - << 'PYEOF'
import os, re

for dirpath, _, filenames in os.walk("."):
    for f in filenames:
        if not f.endswith(".go"):
            continue
        p = os.path.join(dirpath, f)
        with open(p, "r", encoding="utf-8", errors="ignore") as fp:
            content = fp.read()
        if "echPublicName" not in content and "ReplaceECHPublicName" not in content and "patchECHConfigPublicName" not in content:
            continue

        orig = content
        # خنثی‌سازی توابع دستکاری باینری public_name برای جلوگیری از خطای HPKE AAD
        content = re.sub(
            r'func\s+(patchECHConfigPublicName|replaceECHPublicName|RewriteECHPublicName)\s*\([^)]*\)\s*\(\[\]byte,\s*error\)\s*\{',
            r'func \1(echConfig []byte, _ string) ([]byte, error) {\n\treturn echConfig, nil // Disabled to preserve HPKE AAD\n',
            content
        )
        content = re.sub(
            r'func\s+(patchECHConfigPublicName|replaceECHPublicName|RewriteECHPublicName)\s*\([^)]*\)\s*\[\]byte\s*\{',
            r'func \1(echConfig []byte, _ string) []byte {\n\treturn echConfig // Disabled to preserve HPKE AAD\n',
            content
        )
        content = re.sub(r'.*echPublicName.*\n', '', content)

        if content != orig:
            with open(p, "w", encoding="utf-8") as fp:
                fp.write(content)
            print(f"  ✓ Cleaned echPublicName from: {p}")
PYEOF

# ---------------------------------------------------------
# گام ۲: ایجاد فایل transport/internet/tls/mutator.go
# ---------------------------------------------------------
echo "[2/4] Creating transport/internet/tls/mutator.go..."
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
	CarrierGreaseRandom CarrierType = iota // 0x0a0a .. 0xfafa
	CarrierPadding0015                     // 0x0015 Non-Zero Padding
	CarrierLegacyNPN                       // 0x3374 Legacy NPN
)

type PreambleType int

const (
	PreambleNone       PreambleType = iota
	PreambleZeroRecord              // 16 03 01 00 00
	PreambleAlertWarn               // 15 03 01 00 02 01 00
	PreambleCCS                     // 14 03 03 00 01 01
)

type SplitBoundary int

const (
	SplitNone         SplitBoundary = iota
	SplitAfterCiphers               // برش رکورد TLS دقیقاً بعد از لیست CipherSuites
	SplitBeforeSNI                  // برش رکورد TLS دقیقاً قبل از اکستنشن SNI اصلی
)

type DetachMode int

const (
	DetachNone   DetachMode = iota
	DetachSplit5            // ارسال ۵ بایت هدر رکورد در سگمنت جداگانه
	DetachOOB               // ارسال ۵ بایت هدر + ۱ بایت Urgent MSG_OOB
)

// MutationOptions ساختار کامل پارامترهای ۵ بُعدی قابل تنظیم در AlanNG
type MutationOptions struct {
	Enabled         bool
	DecoySNI        string        // دامنه سفید (مثلاً shaparak.ir)
	Carrier         CarrierType   // نوع اکستنشن حامل (grease, pad0015, npn3374)
	TargetOffset    int           // آفست هدف قبل از SNI اصلی (مثلاً 650 یا 1400 برای سرریز MTU)
	HighEntropy     bool          // پر کردن پدینگ با بایت‌های شبه‌تصادفی شبیه به KeyShare
	RepeatCount     int           // تعداد تکرار دامنه سفید در حامل
	RawGreaseInject bool          // تزریق باینری در صورت عدم استفاده از uTLS
	Preamble        PreambleType  // رکورد پیش‌پردازه قبل از ClientHello
	Split           SplitBoundary // برش ساختاری رکورد TLS بدون بریدن رشته SNI
	OuterVersion    uint16        // تغییر نسخه هدر رکورد (مثلاً 0x0302 یا 0x0300)
	Detach          DetachMode    // حالت جداسازی هدر ۵ بایتی و بایت OOB
	OOBByte         byte          // بایت خارج از نوبت
	JitterMinMs     int           // حداقل تاخیر بین سگمنت‌ها (برای دکل‌های 4G/5G)
	JitterMaxMs     int           // حداکثر تاخیر بین سگمنت‌ها
}

var greaseTable = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
	0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
	0xcaca, 0xdada, 0xeaea, 0xfafa,
}

func pickCarrierID(c CarrierType) uint16 {
	switch c {
	case CarrierPadding0015:
		return 0x0015
	case CarrierLegacyNPN:
		return 0x3374
	default:
		return greaseTable[mrand.Intn(len(greaseTable))]
	}
}

// ParseSNIMutationTag تگ #mut= را از انتهای SNI جدا کرده و ساختار تنظیمات را می‌سازد
func ParseSNIMutationTag(rawSNI string) (cleanSNI string, opts MutationOptions) {
	idx := strings.Index(rawSNI, "#mut=")
	if idx == -1 {
		return rawSNI, opts
	}

	cleanSNI = rawSNI[:idx]
	tagPart := rawSNI[idx+5:]

	opts.TargetOffset = 650
	opts.RepeatCount = 1
	opts.OOBByte = 0x78
	opts.JitterMinMs = 2
	opts.JitterMaxMs = 5

	for _, token := range strings.Split(tagPart, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		switch {
		case strings.HasPrefix(token, "decoy:") || strings.HasPrefix(token, "grease:"):
			val := strings.TrimPrefix(strings.TrimPrefix(token, "decoy:"), "grease:")
			if val != "" {
				opts.DecoySNI = val
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
			}
			opts.Enabled = true
		case strings.HasPrefix(token, "split:"):
			switch strings.TrimPrefix(token, "split:") {
			case "cipher":
				opts.Split = SplitAfterCiphers
			case "sni":
				opts.Split = SplitBeforeSNI
			}
			opts.Enabled = true
		case strings.HasPrefix(token, "ver:"):
			switch strings.TrimPrefix(token, "ver:") {
			case "0302":
				opts.OuterVersion = 0x0302
			case "0300":
				opts.OuterVersion = 0x0300
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

// BuildPhantomSNIPayload ساخت پیلود باینری اکستنشن حامل شامل دامنه سفید + پدینگ (صفر یا آنتروپی بالا)
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

// ApplyUTLSGreasePhantomSNI تزریق حامل دامنه سفید در ابتدای اکستنشن‌های uTLS و انتقال SNI اصلی به انتهای پکت
func ApplyUTLSGreasePhantomSNI(uConn *utls.UConn, opts MutationOptions) error {
	if !opts.Enabled || opts.DecoySNI == "" {
		return nil
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		return err
	}

	carrierID := pickCarrierID(opts.Carrier)
	phantomPayload := BuildPhantomSNIPayload(opts)
	phantomExt := &utls.GenericExtension{
		Id:   carrierID,
		Data: phantomPayload,
	}

	exts := uConn.Extensions
	var sniExt utls.TLSExtension
	filtered := make([]utls.TLSExtension, 0, len(exts)+1)

	for _, ext := range exts {
		if _, ok := ext.(*utls.SNIExtension); ok {
			sniExt = ext
			continue
		}
		if opts.Carrier == CarrierPadding0015 {
			if _, isPad := ext.(*utls.UtlsPaddingExtension); isPad {
				continue
			}
		}
		filtered = append(filtered, ext)
	}

	result := make([]utls.TLSExtension, 0, len(filtered)+2)
	result = append(result, phantomExt)

	if sniExt != nil {
		n := len(filtered)
		if n > 0 {
			if _, isPSK := filtered[n-1].(*utls.UtlsPreSharedKeyExtension); isPSK {
				result = append(result, filtered[:n-1]...)
				result = append(result, sniExt, filtered[n-1])
			} else {
				result = append(result, filtered...)
				result = append(result, sniExt)
			}
		} else {
			result = append(result, sniExt)
		}
	} else {
		result = append(result, filtered...)
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

	// ۱. تزریق Raw در صورتی که از crypto/tls استاندارد استفاده شده باشد
	if w.opts.RawGreaseInject && w.opts.DecoySNI != "" {
		if mutatedPkt, err := injectGreasePhantomSNIRaw(packet, w.opts); err == nil {
			packet = mutatedPkt
		}
	}

	// ۲. تغییر نسخه بیرونی هدر رکورد
	outerVer := uint16(0x0301)
	if w.opts.OuterVersion != 0 {
		outerVer = w.opts.OuterVersion
		packet[1] = byte(outerVer >> 8)
		packet[2] = byte(outerVer)
	} else {
		outerVer = binary.BigEndian.Uint16(packet[1:3])
	}

	w.setNoDelay(true)

	// ۳. ارسال رکورد Preamble در سگمنت مستقل اول
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

	// ۴. اعمال برش ساختاری رکورد TLS قبل از SNI (در صورت فعال بودن)
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

	// ۵. ارسال رکورد اصلی (با یا بدون جداسازی هدر ۵ بایتی / OOB)
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

// splitTLSRecordStructurally شکستن یک رکورد Handshake به دو رکورد معتبر TLS در مرز ساختاری بدون بریدن رشته SNI
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
				break
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

	carrierID := pickCarrierID(opts.Carrier)
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

# ---------------------------------------------------------
# گام ۳: پچ هوشمند transport/internet/tls/tls.go
# ---------------------------------------------------------
echo "[3/4] Hooking mutator into transport/internet/tls/tls.go..."
python3 - << 'PYEOF'
import re, sys

tls_go = "transport/internet/tls/tls.go"
with open(tls_go, "r", encoding="utf-8") as fp:
    code = fp.read()

if "ParseSNIMutationTag" in code:
    print("  ✓ tls.go is already hooked.")
    sys.exit(0)

# ۱. هوک کردن تابع Client استاندارد
client_pattern = re.compile(r'return\s+&Conn\{\s*Conn:\s*tls\.Client\(\s*c\s*,\s*tlsConfig\s*\)\s*\}')
client_replacement = """cleanSNI, mutOpts := ParseSNIMutationTag(tlsConfig.ServerName)
	tlsConfig.ServerName = cleanSNI
	if mutOpts.DecoySNI != "" {
		mutOpts.RawGreaseInject = true
	}
	c = NewCustomConnWrapper(c, mutOpts)
	return &Conn{Conn: tls.Client(c, tlsConfig)}"""

code, count1 = client_pattern.subn(client_replacement, code, count=1)

# ۲. هوک کردن تابع UClient (کتابخانه uTLS)
uclient_pattern = re.compile(r'(\w+)\s*:=\s*utls\.UClient\(\s*c\s*,\s*(\w+)\s*,\s*\*fingerprint\s*\)')
def uclient_repl(match):
    uconn_var = match.group(1)
    cfg_var = match.group(2)
    return f"""cleanSNI, mutOpts := ParseSNIMutationTag({cfg_var}.ServerName)
	{cfg_var}.ServerName = cleanSNI
	c = NewCustomConnWrapper(c, mutOpts)
	{uconn_var} := utls.UClient(c, {cfg_var}, *fingerprint)
	if mutOpts.DecoySNI != "" && !mutOpts.RawGreaseInject {{
		_ = ApplyUTLSGreasePhantomSNI({uconn_var}, mutOpts)
	}}"""

code, count2 = uclient_pattern.subn(uclient_repl, code, count=1)

if count1 == 0 and count2 == 0:
    print("❌ Could not find standard Client/UClient patterns in tls.go. Please check tls.go manually.")
    sys.exit(1)

with open(tls_go, "w", encoding="utf-8") as fp:
    fp.write(code)

print(f"  ✓ Hooked tls.go successfully (Client hooked: {count1}, UClient hooked: {count2})")
PYEOF

# ---------------------------------------------------------
# گام ۴: ایجاد Unit Test و تست کامپایل کامل پکیج TLS
# ---------------------------------------------------------
echo "[4/4] Creating unit test and verifying Go build..."
cat << 'TESTEOF' > transport/internet/tls/mutator_test.go
package tls

import (
	"testing"
)

func TestParseSNIMutationTag(t *testing.T) {
	raw := "worker.example.com#mut=decoy:shaparak.ir,carrier:pad0015,offset:1400,entropy:high,preamble:zero,split:sni,ver:0302,oob:oob,jitter:10-30"
	clean, opts := ParseSNIMutationTag(raw)

	if clean != "worker.example.com" {
		t.Fatalf("expected clean SNI 'worker.example.com', got '%s'", clean)
	}
	if !opts.Enabled || opts.DecoySNI != "shaparak.ir" || opts.Carrier != CarrierPadding0015 {
		t.Fatalf("unexpected carrier/decoy options: %+v", opts)
	}
	if opts.TargetOffset != 1400 || !opts.HighEntropy || opts.Preamble != PreambleZeroRecord {
		t.Fatalf("unexpected offset/entropy/preamble: %+v", opts)
	}
	if opts.Split != SplitBeforeSNI || opts.OuterVersion != 0x0302 || opts.Detach != DetachOOB {
		t.Fatalf("unexpected split/ver/detach: %+v", opts)
	}
	if opts.JitterMinMs != 10 || opts.JitterMaxMs != 30 {
		t.Fatalf("unexpected jitter range: %d-%d", opts.JitterMinMs, opts.JitterMaxMs)
	}

	payload := BuildPhantomSNIPayload(opts)
	if len(payload) < 1400 {
		t.Fatalf("expected payload >= 1400 bytes, got %d", len(payload))
	}
}
TESTEOF

go test -v ./transport/internet/tls -run TestParseSNIMutationTag
go build ./main/...

echo "========================================================"
echo "✅ Xray-core is patched, tested, and compiled cleanly!"
echo "========================================================"

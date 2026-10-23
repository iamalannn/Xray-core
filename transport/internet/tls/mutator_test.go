package tls

import (
	"bytes"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestUTLSChromeRecordSplitVerification(t *testing.T) {
	rawSNI := "wallweb8g66f0.pages.DEV#mut=decoy:shaparak.ir,carrier:grease,offset:600,entropy:high,split:sni,ver:0302,jitter:20-30"
	cleanSNI, opts := ParseSNIMutationTag(rawSNI)

	uCfg := &utls.Config{
		ServerName: cleanSNI,
		NextProtos: []string{"http/1.1"},
	}
	uConn := utls.UClient(nil, uCfg, utls.HelloChrome_Auto)
	if err := ApplyUTLSGreasePhantomSNI(uConn, opts); err != nil {
		t.Fatalf("ApplyUTLSGreasePhantomSNI error: %v", err)
	}

	rawHello := uConn.HandshakeState.Hello.Raw
	// بسته‌بندی در یک رکورد TLS مانند کاری که uTLS هنگام ارسال انجام می‌دهد
	fullRecord := make([]byte, 5+len(rawHello))
	fullRecord[0] = 0x16
	fullRecord[1] = 0x03
	fullRecord[2] = 0x01
	fullRecord[3] = byte(len(rawHello) >> 8)
	fullRecord[4] = byte(len(rawHello))
	copy(fullRecord[5:], rawHello)

	splits, ok := splitTLSRecordStructurally(fullRecord, SplitBeforeSNI, 0x0302)
	if !ok {
		t.Fatalf("splitTLSRecordStructurally failed!")
	}

	rec1, rec2 := splits[0], splits[1]
	t.Logf("Rec1 len: %d bytes | Rec2 len: %d bytes", len(rec1), len(rec2))

	if !bytes.Contains(rec1, []byte("shaparak.ir")) {
		t.Fatalf("CRITICAL BUG: Rec1 does NOT contain decoy 'shaparak.ir'!")
	}
	if bytes.Contains(rec1, []byte("wallweb8g66f0.pages.dev")) {
		t.Fatalf("CRITICAL BUG: Rec1 still contains real SNI 'wallweb8g66f0.pages.dev'! DPI will block it!")
	}
	if !bytes.Contains(rec2, []byte("wallweb8g66f0.pages.dev")) {
		t.Fatalf("CRITICAL BUG: Rec2 does NOT contain real SNI 'wallweb8g66f0.pages.dev'!")
	}
	t.Logf("✅ VERIFIED: Rec1 (%d B) ONLY has shaparak.ir, Rec2 (%d B) has wallweb8g66f0.pages.dev!", len(rec1), len(rec2))
}

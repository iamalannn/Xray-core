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

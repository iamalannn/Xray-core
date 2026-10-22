#!/usr/bin/env bash
set -e

echo "========================================================"
echo "   🔧 Smart AST Hooker for Xray-core (tls.go)"
echo "========================================================"

if [ ! -f "transport/internet/tls/tls.go" ]; then
    echo "❌ Error: Run this inside /workspaces/Xray-core"
    exit 1
fi

python3 - << 'PYEOF'
import re, sys

tls_go = "transport/internet/tls/tls.go"
with open(tls_go, "r", encoding="utf-8") as fp:
    code = fp.read()

# اگر قبلاً هوک شده، ابتدا به حالت تمیز برگردانیم
if "ParseSNIMutationTag" in code:
    print("  ℹ️ Already hooked! Re-verifying...")
    sys.exit(0)

# ۱. هوک کردن تابع Client(c net.Conn, ...)
# پیدا کردن هر نوع فراخوانی tls.Client(c, ...)
client_regex = re.compile(r'tls\.Client\(\s*(\w+)\s*,\s*(\w+)\s*\)')
m_client = client_regex.search(code)
hooked_client = False

if m_client:
    conn_var = m_client.group(1)
    cfg_var = m_client.group(2)
    # پیدا کردن ابتدای خطی که tls.Client در آن قرار دارد
    line_start = code.rfind('\n', 0, m_client.start()) + 1
    indent_match = re.match(r'[ \t]*', code[line_start:])
    indent = indent_match.group(0) if indent_match else "\t"

    inject_client = (
        f"{indent}cleanSNI, mutOpts := ParseSNIMutationTag({cfg_var}.ServerName)\n"
        f"{indent}{cfg_var}.ServerName = cleanSNI\n"
        f"{indent}if mutOpts.DecoySNI != \"\" {{\n"
        f"{indent}\tmutOpts.RawGreaseInject = true\n"
        f"{indent}}}\n"
        f"{indent}{conn_var} = NewCustomConnWrapper({conn_var}, mutOpts)\n"
    )
    code = code[:line_start] + inject_client + code[line_start:]
    hooked_client = True
    print(f"  ✓ Hooked standard tls.Client({conn_var}, {cfg_var})")

# ۲. هوک کردن تابع UClient (پشتیبانی از تمام نسخه‌های Xray و uTLS)
uclient_regex = re.compile(r'(\w+)\s*(?::=|=)\s*utls\.UClient\(\s*(\w+)\s*,\s*(\w+)\s*,[^)]+\)')
m_uclient = uclient_regex.search(code)
hooked_uclient = False

if m_uclient:
    uconn_var = m_uclient.group(1)
    conn_var = m_uclient.group(2)
    cfg_var = m_uclient.group(3)

    line_start = code.rfind('\n', 0, m_uclient.start()) + 1
    line_end = code.find('\n', m_uclient.end())
    if line_end == -1:
        line_end = len(code)

    indent_match = re.match(r'[ \t]*', code[line_start:])
    indent = indent_match.group(0) if indent_match else "\t"

    original_line = code[line_start:line_end]

    inject_uclient = (
        f"{indent}cleanSNI, mutOpts := ParseSNIMutationTag({cfg_var}.ServerName)\n"
        f"{indent}{cfg_var}.ServerName = cleanSNI\n"
        f"{indent}{conn_var} = NewCustomConnWrapper({conn_var}, mutOpts)\n"
        f"{original_line}\n"
        f"{indent}if mutOpts.DecoySNI != \"\" && !mutOpts.RawGreaseInject {{\n"
        f"{indent}\t_ = ApplyUTLSGreasePhantomSNI({uconn_var}, mutOpts)\n"
        f"{indent}}}"
    )
    code = code[:line_start] + inject_uclient + code[line_end:]
    hooked_uclient = True
    print(f"  ✓ Hooked uTLS utls.UClient -> {uconn_var}({conn_var}, {cfg_var})")

if not hooked_client and not hooked_uclient:
    print("❌ Could not match tls.Client or utls.UClient! Printing tls.go for inspection:")
    print("--------------------------------------------------")
    print(code)
    print("--------------------------------------------------")
    sys.exit(1)

with open(tls_go, "w", encoding="utf-8") as fp:
    fp.write(code)

print("  ✓ Successfully updated transport/internet/tls/tls.go")
PYEOF

echo "[Testing Go Compilation & Unit Tests...]"
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
echo "✅ Xray-core Hooked, Tested, and Compiled Successfully!"
echo "========================================================"

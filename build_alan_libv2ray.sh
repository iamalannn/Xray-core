#!/usr/bin/env bash
set -e

echo "========================================================"
echo "   📦 AlanNG - AndroidLibXrayLite Builder (Clean Fix)"
echo "========================================================"

ALAN_XRAY_REPO="github.com/iamalannn/Xray-core"
ALAN_XRAY_COMMIT="7ad072ff9daac3d985f3da98c5e5a4ad57505063"

# ۱. بازگرداندن go.mod و go.sum به وضعیت سالم اولیه برای پاک شدن خطای version "main"
echo "🧹 Resetting go.mod and go.sum to clean state..."
git checkout -- go.mod go.sum 2>/dev/null || true

# در صورتی که فایل در git تغییر نکرده بود ولی خط خراب داشت، با پایتون هر نوع replace قبلی xray-core را تمیز می‌کنیم
python3 - << 'PYEOF'
with open("go.mod", "r", encoding="utf-8") as fp:
    lines = fp.readlines()

cleaned = [l for l in lines if "iamalannn/Xray-core" not in l and "xtls/xray-core =>" not in l]
with open("go.mod", "w", encoding="utf-8") as fp:
    fp.writelines(cleaned)
PYEOF

# ۲. تنظیم متغیرهای محیطی Go برای عبور از خطای SumDB
export GOPROXY="https://proxy.golang.org,direct"
export GONOPROXY="github.com/iamalannn/*"
export GONOSUMDB="github.com/iamalannn/*,golang.zx2c4.com/*"

# ۳. پاکسازی هش‌های قدیمی از go.sum تا از نو ساخته شوند
if [ -f "go.sum" ]; then
    sed -i '/golang.zx2c4.com\/wireguard/d' go.sum
    sed -i '/github.com\/xtls\/xray-core/d' go.sum
    sed -i '/github.com\/iamalannn\/Xray-core/d' go.sum
fi

# ۴. دریافت نسخه دقیق pseudo-version با استفاده از go get و ثبت در replace
echo "🔗 Linking github.com/xtls/xray-core to ${ALAN_XRAY_REPO}@${ALAN_XRAY_COMMIT}..."
go mod edit -replace "github.com/xtls/xray-core=${ALAN_XRAY_REPO}@${ALAN_XRAY_COMMIT}"
go mod tidy

echo "✅ go.mod and go.sum updated cleanly!"
grep "xray-core" go.mod || true

# ۵. بررسی و نصب gomobile و gobind
export PATH="$PATH:$(go env GOPATH)/bin"
if ! command -v gomobile &> /dev/null; then
    echo "⚙️ Installing gomobile & gobind..."
    go install golang.org/x/mobile/cmd/gomobile@latest
    go install golang.org/x/mobile/cmd/gobind@latest
fi

# ۶. بررسی و تنظیم Android SDK & NDK
if [ -z "${ANDROID_HOME}" ] && [ -z "${ANDROID_SDK_ROOT}" ]; then
    for candidate in "/usr/local/lib/android/sdk" "$HOME/Android/Sdk" "$HOME/android-sdk" "/opt/android-sdk"; do
        if [ -d "$candidate" ]; then
            export ANDROID_HOME="$candidate"
            export ANDROID_SDK_ROOT="$candidate"
            break
        fi
    done
fi

if [ -z "${ANDROID_HOME}" ] || [ ! -d "${ANDROID_HOME}/ndk" ]; then
    echo "📥 Installing minimal Android SDK & NDK (r26b) for gomobile..."
    SDK_DIR="$HOME/android-sdk"
    mkdir -p "$SDK_DIR/cmdline-tools"
    if [ ! -f "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" ]; then
        curl -sSL https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -o /tmp/cmdtools.zip
        unzip -q /tmp/cmdtools.zip -d "$SDK_DIR/cmdline-tools"
        mv "$SDK_DIR/cmdline-tools/cmdline-tools" "$SDK_DIR/cmdline-tools/latest"
        rm -f /tmp/cmdtools.zip
    fi
    yes | "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" --licenses > /dev/null || true
    "$SDK_DIR/cmdline-tools/latest/bin/sdkmanager" "platforms;android-34" "ndk;26.2.11394342"
    export ANDROID_HOME="$SDK_DIR"
    export ANDROID_SDK_ROOT="$SDK_DIR"
    export ANDROID_NDK_HOME="$SDK_DIR/ndk/26.2.11394342"
else
    LATEST_NDK=$(ls -1 "${ANDROID_HOME}/ndk" | sort -V | tail -n 1)
    export ANDROID_NDK_HOME="${ANDROID_HOME}/ndk/${LATEST_NDK}"
fi

echo "🛠 ANDROID_HOME=${ANDROID_HOME}"
echo "🛠 ANDROID_NDK_HOME=${ANDROID_NDK_HOME}"

# ۷. کامپایل فایل libv2ray.aar
gomobile init
echo "🚀 Compiling libv2ray.aar with AlanNG 5D Anti-DPI Core..."
gomobile bind -v -androidapi 21 -trimpath -ldflags='-s -w -buildid=' -o libv2ray.aar ./

ls -lh libv2ray.aar
echo "========================================================"
echo "✅ SUCCESS! libv2ray.aar is built and ready!"
echo "========================================================"

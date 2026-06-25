#!/bin/bash
set -euo pipefail

BUILD_TYPE="${1:-release}"
OUTPUT_DIR="./build/outputs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
APK_NAME="rasp_shield_${BUILD_TYPE}_${TIMESTAMP}.apk"

echo "======================================"
echo " RASP Shield APK Builder"
echo " Build type : $BUILD_TYPE"
echo " Output dir : $OUTPUT_DIR"
echo " Timestamp  : $TIMESTAMP"
echo "======================================"

mkdir -p "$OUTPUT_DIR"

echo "Building Docker image..."
docker compose -f docker-compose.build.yml build flutter-builder

echo "Running Flutter build ($BUILD_TYPE)..."
docker compose -f docker-compose.build.yml run --rm \
  flutter-builder \
  sh -c "
    flutter clean &&
    flutter pub get &&
    flutter build apk --${BUILD_TYPE} \
      --obfuscate \
      --split-debug-info=/app/build/debug-info
  "

# Copy APK with timestamp
SRC="build/app/outputs/flutter-apk/app-${BUILD_TYPE}.apk"
if [ -f "$SRC" ]; then
  cp "$SRC" "$OUTPUT_DIR/$APK_NAME"
  echo ""
  echo "✅ APK ready:"
  ls -lh "$OUTPUT_DIR/$APK_NAME"
else
  echo "❌ APK not found at: $SRC"
  exit 1
fi

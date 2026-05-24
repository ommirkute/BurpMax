#!/bin/bash
# BurpMax v1.0.0 Build Script
# Requirements: JDK 17+
# Usage: ./build.sh

set -e

STUB_DIR="burp-stub"
SRC_DIR="src/main/java"
STUB_OUT="build/stub-classes"
OUT_DIR="build/classes"
JAR_NAME="burpmax-1.0.0.jar"

echo "BurpMax v1.0.0 Build"
echo "========================"

rm -rf "$OUT_DIR" "$STUB_OUT"
mkdir -p "$OUT_DIR" "$STUB_OUT"

# Step 1: Compile Burp API stubs + bundled libs (compile-time only for burp/, bundled for org/)
echo "[1/4] Compiling Burp API stubs..."
find "$STUB_DIR" -name "*.java" > /tmp/burpmax_stubs.txt
javac --release 17 -encoding UTF-8 -d "$STUB_OUT" @/tmp/burpmax_stubs.txt

# Step 2: Compile main sources against stub classpath
echo "[2/4] Compiling $(find $SRC_DIR -name '*.java' | wc -l | tr -d ' ') source files..."
find "$SRC_DIR" -name "*.java" > /tmp/burpmax_sources.txt
javac --release 17 -encoding UTF-8 \
  -cp "$STUB_OUT" \
  -d "$OUT_DIR" \
  -sourcepath "$SRC_DIR" \
  @/tmp/burpmax_sources.txt

# Step 3: Package JAR
# - burp/ stub classes are excluded (Burp provides real API at runtime)
# - org/json classes are INCLUDED (our bundled JSON implementation, not provided by Burp)
echo "[3/4] Packaging $JAR_NAME..."

# Start with our compiled sources
jar cfm "build/$JAR_NAME" build/MANIFEST.MF -C "$OUT_DIR" .

# Bundle org/json from stub-classes (runtime dependency not provided by Burp)
jar uf "build/$JAR_NAME" -C "$STUB_OUT" org

# Step 4: Verify
JAR_SIZE=$(du -h "build/$JAR_NAME" | cut -f1)
CLASS_COUNT=$(jar tf "build/$JAR_NAME" | grep '\.class$' | wc -l | tr -d ' ')
HAS_BURP_STUBS=$(jar tf "build/$JAR_NAME" | grep '^burp/' | wc -l | tr -d ' ')
HAS_JSON=$(jar tf "build/$JAR_NAME" | grep '^org/json/' | wc -l | tr -d ' ')

echo "[4/4] Verification..."
echo "      JAR size:    $JAR_SIZE"
echo "      Classes:     $CLASS_COUNT"
echo "      Burp stubs:  $HAS_BURP_STUBS (must be 0)"
echo "      org/json:    $HAS_JSON (must be > 0)"

if [ "$HAS_BURP_STUBS" != "0" ]; then
  echo "ERROR: Burp stub classes found in JAR. Build failed."
  exit 1
fi

if [ "$HAS_JSON" = "0" ]; then
  echo "ERROR: org/json classes missing from JAR. Session save will not work."
  exit 1
fi

echo ""
echo "Build complete: build/$JAR_NAME"
echo ""
echo "To load in Burp Suite:"
echo "  Extensions > Add > Extension Type: Java > Select build/$JAR_NAME"

#!/usr/bin/env bash

# Simple runner for demo Java programs using ShardingSphere JDBC (Encrypt-only via config)
# Layout expected by this script:
#  - Java sources:   ./demo/*.java
#  - Libraries(JAR): ./lib/*.jar   (include shardingsphere-jdbc, mysql-connector-j, HikariCP, snakeyaml, slf4j-impl, etc.)
#  - Config:         ./config/*.yaml
#
# Usage:
#  - ./run-demo.sh                    # auto-detect main class (AesEncryptTest or MinimalEncryptExample)
#  - ./run-demo.sh -m MainClassName   # run specific main class
#  - MAIN_CLASS=YourMain ./run-demo.sh
#
# Notes:
#  - Ensure your Java code uses a URL like:
#      jdbc:shardingsphere:config/config-aes-mysql.yaml
#    so the relative path resolves correctly from project root.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_DIR="$ROOT_DIR/demo"
LIB_DIR="$ROOT_DIR/lib"
CONFIG_DIR="$ROOT_DIR/config"
BUILD_DIR="$DEMO_DIR/target-classes"

usage() {
  echo "Usage: $0 [-m MainClass]" >&2
}

MAIN_CLASS="${MAIN_CLASS:-}"
while getopts ":m:h" opt; do
  case $opt in
    m) MAIN_CLASS="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

echo "== ShardingSphere JDBC Demo Runner =="

# Basic checks
if ! command -v javac >/dev/null 2>&1; then
  echo "Error: javac not found. Please install JDK 8+." >&2
  exit 1
fi
if ! command -v java >/dev/null 2>&1; then
  echo "Error: java not found. Please install JDK 8+." >&2
  exit 1
fi

if [ ! -d "$DEMO_DIR" ]; then
  echo "Error: demo directory not found at $DEMO_DIR" >&2
  exit 1
fi
if [ ! -d "$LIB_DIR" ]; then
  echo "Error: lib directory not found at $LIB_DIR (put required jars here)." >&2
  exit 1
fi
if [ ! -d "$CONFIG_DIR" ]; then
  echo "Warning: config directory not found at $CONFIG_DIR (ensure your code uses a valid config path)."
fi

# Compose classpath from lib/*.jar
CP=""
shopt -s nullglob
JARS=("$LIB_DIR"/*.jar)
if [ ${#JARS[@]} -eq 0 ]; then
  echo "Error: no jars found in $LIB_DIR. Add shardingsphere-jdbc, mysql-connector-j, HikariCP, snakeyaml, slf4j-impl, etc." >&2
  exit 1
fi
for j in "${JARS[@]}"; do
  if jar tf "$j" >/dev/null 2>&1; then
    if [ -z "$CP" ]; then CP="$j"; else CP="$CP:$j"; fi
  else
    echo "Warning: skipping invalid jar: $j" >&2
  fi
done
shopt -u nullglob

mkdir -p "$BUILD_DIR"

# Compile all demo Java sources
echo "Compiling Java sources in $DEMO_DIR ..."
SRC_FILES=("$DEMO_DIR"/*.java)
if [ ${#SRC_FILES[@]} -eq 0 ]; then
  echo "Error: no Java sources found in $DEMO_DIR" >&2
  exit 1
fi
javac -d "$BUILD_DIR" -cp "$CP" "${SRC_FILES[@]}"
echo "Compilation finished."

# Auto-detect main class if not specified
if [ -z "$MAIN_CLASS" ]; then
  if [ -f "$DEMO_DIR/AesEncryptTest.java" ]; then
    MAIN_CLASS="AesEncryptTest"
  elif [ -f "$DEMO_DIR/MinimalEncryptExample.java" ]; then
    MAIN_CLASS="MinimalEncryptExample"
  else
    # Fallback: pick first public class name from sources (best-effort)
    CANDIDATE=$(sed -n 's/^public\s\+class\s\+\([A-Za-z0-9_]*\).*/\1/p' "$DEMO_DIR"/*.java | head -n1 || true)
    if [ -n "$CANDIDATE" ]; then
      MAIN_CLASS="$CANDIDATE"
    else
      echo "Error: cannot auto-detect main class. Use -m MainClassName to specify." >&2
      exit 1
    fi
  fi
fi

echo "Running main class: $MAIN_CLASS"
echo "Hint: ensure your code uses jdbc:shardingsphere:config/<your-config.yaml> or an absolute path."

exec java -cp "$BUILD_DIR:$CP" "$MAIN_CLASS"


#!/bin/bash
# SlipGate installer — download binary and run `slipgate install`
set -e

REPO="anonvector/slipgate"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[1;36m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; exit 1; }

# Check root
[[ $EUID -ne 0 ]] && error "This script must be run as root (sudo)"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       error "Unsupported architecture: $ARCH" ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
[[ "$OS" != "linux" ]] && error "SlipGate only supports Linux"

BINARY="slipgate-${OS}-${ARCH}"
URL="https://github.com/${REPO}/releases/latest/download/${BINARY}"

echo -e "${CYAN}"
echo "   _____ _ _       _____       _       "
echo "  / ____| (_)     / ____|     | |      "
echo " | (___ | |_ _ __| |  __  __ _| |_ ___ "
echo "  \\___ \\| | | '_ \\ | |_ |/ _\` | __/ _ \\"
echo "  ____) | | | |_) | |__| | (_| | ||  __/"
echo " |_____/|_|_| .__/ \\_____|\\__,_|\\__\\___|"
echo "             | |                         "
echo "             |_|                         "
echo -e "${NC}"

info "Downloading slipgate ($OS/$ARCH)..."
if command -v curl &>/dev/null; then
    curl -fsSL "$URL" -o "${INSTALL_DIR}/slipgate"
elif command -v wget &>/dev/null; then
    wget -qO "${INSTALL_DIR}/slipgate" "$URL"
else
    error "Neither curl nor wget found"
fi

chmod +x "${INSTALL_DIR}/slipgate"

info "Running slipgate install..."
if ! "${INSTALL_DIR}/slipgate" install </dev/tty; then
    error "slipgate install failed — run 'sudo slipgate install' to retry"
fi

info "Done! Run 'sudo slipgate' to get started."

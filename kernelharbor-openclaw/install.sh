#!/usr/bin/env bash
set -uo pipefail

REPO_URL="${KH_REPO:-https://github.com/fr4nsyz/KernelHarbor.git}"
KH_DIR="${KH_DIR:-$HOME/kernelharbor}"
GO_VERSION="${GO_VERSION:-1.25.0}"
FALCO_VERSION="${FALCO_VERSION:-latest}"
SIDEKICK_VERSION="${SIDEKICK_VERSION:-2.30.0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
err()   { echo -e "${RED}✗${NC} $1"; }

echo "KernelHarbor — Quick Install"
echo "============================"
echo ""

detect_os() {
  if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &>/dev/null; then echo "debian"
    elif command -v dnf &>/dev/null; then echo "fedora"
    elif command -v yum &>/dev/null; then echo "rhel"
    else echo "linux"
    fi
  elif [[ "$OSTYPE" == "darwin"* ]]; then echo "macos"
  else echo "unknown"
  fi
}

OS=$(detect_os)

has_sudo() {
  command -v sudo &>/dev/null && sudo -n true &>/dev/null 2>&1
}

install_go() {
  if command -v go &>/dev/null; then
    info "Go already installed: $(go version)"
    return
  fi
  echo "Installing Go $GO_VERSION..."
  local arch="amd64"
  [[ "$(uname -m)" == "aarch64" ]] && arch="arm64"
  local tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o /tmp/go.tar.gz || { err "Failed to download Go"; return 1; }
  if has_sudo; then
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  else
    rm -rf /usr/local/go 2>/dev/null || true
    tar -C /usr/local -xzf /tmp/go.tar.gz 2>/dev/null || {
      err "Need sudo or write access to /usr/local to install Go"
      rm /tmp/go.tar.gz
      return 1
    }
  fi
  rm /tmp/go.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  if ! grep -q '/usr/local/go/bin' ~/.profile 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
  fi
  info "Go $GO_VERSION installed"
}

install_falco() {
  if command -v falco &>/dev/null; then
    info "Falco already installed: $(falco --version 2>&1 | head -1)"
    return 0
  fi
  if ! has_sudo; then
    warn "Skipping Falco (requires passwordless sudo). Install manually: https://falco.org/docs/install/"
    return 0
  fi
  echo "Installing Falco..."
  case "$OS" in
    debian)
      curl -fsSL https://falco.org/repo/falcosecurity-3674BA9F.asc | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null || true
      echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list >/dev/null
      sudo apt-get update -qq 2>/dev/null || true
      sudo apt-get install -y -qq falco 2>/dev/null || {
        warn "Package install failed, trying script..."
        curl -fsSL https://falco.org/script/install | sudo bash 2>/dev/null || {
          warn "Falco install script failed. Install manually: https://falco.org/docs/install/"
          return 0
        }
      }
      ;;
    fedora|rhel)
      sudo dnf install -y "https://download.falco.org/packages/rpm/falco-${FALCO_VERSION}-x86_64.rpm" 2>/dev/null || {
        warn "RPM install failed, trying script..."
        curl -fsSL https://falco.org/script/install | sudo bash 2>/dev/null || {
          warn "Falco install script failed. Install manually: https://falco.org/docs/install/"
          return 0
        }
      }
      ;;
    macos)
      brew install falcosecurity/tap/falco 2>/dev/null || brew install --cask falco 2>/dev/null || {
        warn "Falco brew install failed. Install manually: https://falco.org/docs/install/"
        return 0
      }
      ;;
    *)
      warn "Unsupported OS. Install Falco manually: https://falco.org/docs/install/"
      return 0
      ;;
  esac
  info "Falco installed"
}

install_sidekick() {
  if command -v falcosidekick &>/dev/null; then
    info "falcosidekick already installed: $(falcosidekick --version 2>&1 | head -1)"
    return 0
  fi
  echo "Installing falcosidekick $SIDEKICK_VERSION..."
  local arch="amd64"
  [[ "$(uname -m)" == "aarch64" ]] && arch="arm64"
  local url="https://github.com/falcosecurity/falcosidekick/releases/download/${SIDEKICK_VERSION}/falcosidekick_${SIDEKICK_VERSION}_linux_${arch}.tar.gz"
  curl -fsSL "$url" -o /tmp/falcosidekick.tar.gz 2>/dev/null || {
    url="https://github.com/falcosecurity/falcosidekick/releases/latest/download/falcosidekick_${SIDEKICK_VERSION}_linux_${arch}.tar.gz"
    curl -fsSL "$url" -o /tmp/falcosidekick.tar.gz 2>/dev/null || {
      warn "Failed to download falcosidekick. Install manually: https://github.com/falcosecurity/falcosidekick/releases"
      return 0
    }
  }
  if has_sudo; then
    sudo tar -C /usr/local/bin -xzf /tmp/falcosidekick.tar.gz falcosidekick 2>/dev/null || {
      sudo tar -C /usr/local/bin -xzf /tmp/falcosidekick.tar.gz 2>/dev/null
    }
    sudo chmod +x /usr/local/bin/falcosidekick 2>/dev/null || true
  else
    tar -C /usr/local/bin -xzf /tmp/falcosidekick.tar.gz falcosidekick 2>/dev/null || {
      mkdir -p /tmp/kh-sidekick
      tar -xzf /tmp/falcosidekick.tar.gz -C /tmp/kh-sidekick 2>/dev/null || true
      if [ -f /tmp/kh-sidekick/falcosidekick ]; then
        cp /tmp/kh-sidekick/falcosidekick /usr/local/bin/falcosidekick 2>/dev/null || {
          warn "Need sudo to install falcosidekick to /usr/local/bin"
          warn "  Binary extracted at /tmp/kh-sidekick/falcosidekick — move it manually"
          rm /tmp/falcosidekick.tar.gz
          return 0
        }
      fi
      rm -rf /tmp/kh-sidekick
    }
  fi
  rm /tmp/falcosidekick.tar.gz
  info "falcosidekick $SIDEKICK_VERSION installed"
}

# Main — errors in optional components are non-fatal
install_go || { err "Go installation failed"; exit 1; }
install_falco
install_sidekick

echo ""
echo "Cloning KernelHarbor..."
if [ -d "$KH_DIR" ]; then
  info "Already cloned at $KH_DIR"
else
  git clone --depth=1 "$REPO_URL" "$KH_DIR" || { err "Clone failed"; exit 1; }
  info "Cloned to $KH_DIR"
fi

cd "$KH_DIR/kernelharbor-openclaw" || { err "Directory not found: $KH_DIR/kernelharbor-openclaw"; exit 1; }

echo ""
echo "Installing npm dependencies..."
npm install --silent 2>/dev/null || npm install || { warn "npm install failed"; }

echo ""
echo "Running setup..."
node ./cli/setup.mjs || { warn "setup.mjs failed — check the output above"; }

echo ""
echo "===================================="
echo -e "${GREEN}KernelHarbor installed!${NC}"
echo ""
echo "  cd $KH_DIR/kernelharbor-openclaw"
echo "  ./cli/status.mjs       # check status"
echo "  ./cli/dashboard.mjs    # start dashboard"
echo "===================================="

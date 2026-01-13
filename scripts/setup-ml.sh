#!/bin/bash
# Setup ML detection layer with tihilya ModernBERT model
#
# This script downloads and configures everything needed for ML-based
# prompt injection detection using the Apache 2.0 licensed tihilya model.
#
# Usage:
#   ./scripts/setup-ml.sh              # Full setup (model + ONNX Runtime)
#   ./scripts/setup-ml.sh model        # Download model only
#   ./scripts/setup-ml.sh onnx         # Download ONNX Runtime only
#   ./scripts/setup-ml.sh tokenizers   # Build tokenizers library only
#   ./scripts/setup-ml.sh verify       # Verify installation
#   ./scripts/setup-ml.sh clean        # Remove downloaded files

set -euo pipefail

# Configuration
MODEL_NAME="tihilya/modernbert-base-prompt-injection-detection"
MODEL_DIR="./models/modernbert-base"
ONNX_VERSION="1.23.2"
ONNX_DIR="${HOME}/onnxruntime"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect platform
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    case "$os" in
        darwin)
            if [[ "$arch" == "arm64" ]]; then
                echo "osx-arm64"
            else
                echo "osx-x64"
            fi
            ;;
        linux)
            if [[ "$arch" == "aarch64" ]]; then
                echo "linux-aarch64"
            else
                echo "linux-x64"
            fi
            ;;
        *)
            error "Unsupported platform: $os-$arch"
            ;;
    esac
}

# Download model from HuggingFace
download_model() {
    info "Downloading tihilya ModernBERT model..."

    # Check if huggingface-cli is available
    if command -v huggingface-cli &> /dev/null; then
        info "Using huggingface-cli..."
        mkdir -p "$MODEL_DIR"
        huggingface-cli download "$MODEL_NAME" --local-dir "$MODEL_DIR" --local-dir-use-symlinks False
    elif command -v python3 &> /dev/null; then
        info "Using Python huggingface_hub..."
        python3 << EOF
from huggingface_hub import snapshot_download
snapshot_download(
    repo_id="$MODEL_NAME",
    local_dir="$MODEL_DIR",
    local_dir_use_symlinks=False
)
print("Model downloaded successfully!")
EOF
    else
        # Manual download with curl
        info "Downloading model files with curl..."
        mkdir -p "$MODEL_DIR"

        BASE_URL="https://huggingface.co/$MODEL_NAME/resolve/main"
        FILES=(
            "config.json"
            "model.onnx"
            "special_tokens_map.json"
            "tokenizer_config.json"
            "tokenizer.json"
        )

        for file in "${FILES[@]}"; do
            info "  Downloading $file..."
            curl -sL "$BASE_URL/$file" -o "$MODEL_DIR/$file"
        done
    fi

    # Verify model files
    if [[ -f "$MODEL_DIR/model.onnx" ]] && [[ -f "$MODEL_DIR/tokenizer.json" ]]; then
        local size=$(du -sh "$MODEL_DIR" | cut -f1)
        info "Model downloaded successfully ($size)"
    else
        error "Model download failed - missing required files"
    fi
}

# Download ONNX Runtime
download_onnx() {
    local platform=$(detect_platform)
    local onnx_file="onnxruntime-${platform}-${ONNX_VERSION}.tgz"
    local onnx_url="https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/${onnx_file}"
    local onnx_extract_dir="${ONNX_DIR}-${platform}-${ONNX_VERSION}"

    info "Downloading ONNX Runtime ${ONNX_VERSION} for ${platform}..."

    if [[ -d "$onnx_extract_dir" ]]; then
        info "ONNX Runtime already exists at $onnx_extract_dir"
        return 0
    fi

    # Download
    cd "$HOME"
    if [[ ! -f "$onnx_file" ]]; then
        curl -sLO "$onnx_url"
    fi

    # Extract
    tar -xzf "$onnx_file"
    rm -f "$onnx_file"

    info "ONNX Runtime extracted to: $onnx_extract_dir"

    # Print library path for export
    echo ""
    echo "Add to your shell profile (~/.zshrc or ~/.bashrc):"
    echo "  export CGO_LDFLAGS=\"-L${onnx_extract_dir}/lib\""
    if [[ "$platform" == osx-* ]]; then
        echo "  export DYLD_LIBRARY_PATH=\"${onnx_extract_dir}/lib:\$DYLD_LIBRARY_PATH\""
    else
        echo "  export LD_LIBRARY_PATH=\"${onnx_extract_dir}/lib:\$LD_LIBRARY_PATH\""
    fi
}

# Build tokenizers library (macOS only - Linux has pre-built)
build_tokenizers() {
    local platform=$(detect_platform)

    if [[ "$platform" == linux-* ]]; then
        info "Downloading pre-built tokenizers for Linux..."
        sudo curl -sL "https://github.com/knights-analytics/hugot/releases/latest/download/libtokenizers.a" \
            -o /usr/local/lib/libtokenizers.a
        info "Tokenizers installed to /usr/local/lib/libtokenizers.a"
        return 0
    fi

    info "Building tokenizers library for macOS..."

    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        warn "Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi

    # Clone and build
    local tokenizers_dir="${HOME}/tokenizers"
    if [[ ! -d "$tokenizers_dir" ]]; then
        git clone --depth 1 https://github.com/daulet/tokenizers.git "$tokenizers_dir"
    fi

    cd "$tokenizers_dir"
    make build

    info "Tokenizers built at: ${tokenizers_dir}/libtokenizers.a"
    echo ""
    echo "Add to CGO_LDFLAGS:"
    echo "  export CGO_LDFLAGS=\"\$CGO_LDFLAGS -L${tokenizers_dir}\""
}

# Verify installation
verify_install() {
    info "Verifying ML setup..."
    local errors=0

    # Check model
    if [[ -f "$MODEL_DIR/model.onnx" ]]; then
        local model_size=$(du -h "$MODEL_DIR/model.onnx" | cut -f1)
        info "  Model: OK ($model_size)"
    else
        warn "  Model: NOT FOUND"
        errors=$((errors + 1))
    fi

    # Check ONNX Runtime
    local platform=$(detect_platform)
    local onnx_lib="${ONNX_DIR}-${platform}-${ONNX_VERSION}/lib"
    if [[ -d "$onnx_lib" ]]; then
        info "  ONNX Runtime: OK"
    else
        warn "  ONNX Runtime: NOT FOUND at $onnx_lib"
        errors=$((errors + 1))
    fi

    # Check tokenizers
    local tokenizers_path=""
    if [[ -f "${HOME}/tokenizers/libtokenizers.a" ]]; then
        tokenizers_path="${HOME}/tokenizers/libtokenizers.a"
    elif [[ -f "/usr/local/lib/libtokenizers.a" ]]; then
        tokenizers_path="/usr/local/lib/libtokenizers.a"
    fi

    if [[ -n "$tokenizers_path" ]]; then
        info "  Tokenizers: OK ($tokenizers_path)"
    else
        warn "  Tokenizers: NOT FOUND"
        errors=$((errors + 1))
    fi

    echo ""
    if [[ $errors -eq 0 ]]; then
        info "All components verified!"
        print_env_setup
        return 0
    else
        error "Missing $errors component(s). Run './scripts/setup-ml.sh' to install."
    fi
}

# Print environment setup
print_env_setup() {
    local platform=$(detect_platform)
    local onnx_lib="${ONNX_DIR}-${platform}-${ONNX_VERSION}/lib"
    local tokenizers_lib=""

    if [[ -f "${HOME}/tokenizers/libtokenizers.a" ]]; then
        tokenizers_lib="${HOME}/tokenizers"
    elif [[ -f "/usr/local/lib/libtokenizers.a" ]]; then
        tokenizers_lib="/usr/local/lib"
    fi

    echo ""
    echo "Environment setup (add to ~/.zshrc or ~/.bashrc):"
    echo "─────────────────────────────────────────────────"
    echo "export CGO_LDFLAGS=\"-L${onnx_lib} -L${tokenizers_lib}\""
    if [[ "$platform" == osx-* ]]; then
        echo "export DYLD_LIBRARY_PATH=\"${onnx_lib}:\$DYLD_LIBRARY_PATH\""
    else
        echo "export LD_LIBRARY_PATH=\"${onnx_lib}:\$LD_LIBRARY_PATH\""
    fi
    echo "export HUGOT_MODEL_PATH=\"\$(pwd)/models/modernbert-base\""
    echo ""
    echo "Then build and test:"
    echo "  go build -tags ORT ./cmd/gateway"
    echo "  go test -tags ORT ./pkg/ml/... -v -run Integration"
}

# Clean downloaded files
clean() {
    info "Cleaning ML assets..."

    if [[ -d "$MODEL_DIR" ]]; then
        rm -rf "$MODEL_DIR"
        info "Removed model directory"
    fi

    local platform=$(detect_platform)
    local onnx_extract_dir="${ONNX_DIR}-${platform}-${ONNX_VERSION}"
    if [[ -d "$onnx_extract_dir" ]]; then
        rm -rf "$onnx_extract_dir"
        info "Removed ONNX Runtime"
    fi

    info "Clean complete"
}

# Full setup
full_setup() {
    echo "═══════════════════════════════════════════════════════════"
    echo "  Citadel ML Detection Layer Setup"
    echo "  Model: tihilya ModernBERT-base (Apache 2.0)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    download_model
    echo ""
    download_onnx
    echo ""
    build_tokenizers
    echo ""
    verify_install
}

# Main
case "${1:-full}" in
    full|"")
        full_setup
        ;;
    model)
        download_model
        ;;
    onnx)
        download_onnx
        ;;
    tokenizers)
        build_tokenizers
        ;;
    verify)
        verify_install
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  full       Full setup (model + ONNX + tokenizers) [default]"
        echo "  model      Download tihilya model from HuggingFace"
        echo "  onnx       Download ONNX Runtime ${ONNX_VERSION}"
        echo "  tokenizers Build tokenizers library"
        echo "  verify     Verify installation"
        echo "  clean      Remove downloaded files"
        echo "  help       Show this help"
        ;;
    *)
        error "Unknown command: $1. Use '$0 help' for usage."
        ;;
esac

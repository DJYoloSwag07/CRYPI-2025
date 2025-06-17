#!/usr/bin/env bash
# Installer for the Identity ZKP Prover
# Automates building, key setup, custom protocol registration, and dependencies check.

set -euo pipefail

# Variables
CARGO_PATH="$(pwd)"
IDENTITY_BIN_DIR="$HOME/.cargo/bin"
IDENTITY_BIN="$IDENTITY_BIN_DIR/identity"
IDENTITY_HOME="$HOME/.identity"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/identity-protocol.desktop"

# 1. Check for required commands
echo "Checking dependencies..."
for cmd in cargo xdg-mime update-desktop-database zenity; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "Error: '$cmd' is not installed. Please install it and retry." >&2
    exit 1
  fi
done

echo "All dependencies are met."

# 2. Build and install the binary
echo "Building and installing the 'identity' binary..."
cargo install --path "$CARGO_PATH"
echo "Installed 'identity' to: $IDENTITY_BIN" 

echo "Linking 'identity' into a directory on your PATH..."
# 1) Try /usr/local/bin
if [ -w /usr/local/bin ]; then
  TARGET_DIR=/usr/local/bin
  ln -sf "$IDENTITY_BIN" "$TARGET_DIR/identity"
elif [ -w "$HOME/.local/bin" ]; then
  TARGET_DIR="$HOME/.local/bin"
  mkdir -p "$TARGET_DIR"
  ln -sf "$IDENTITY_BIN" "$TARGET_DIR/identity"
else;
  echo "Nowhere to install the binary, please add $IDENTITY_BIN to your PATH"
fi


# 3. Create identity home and copy keys
echo "Setting up keys in '$IDENTITY_HOME'..."
mkdir -p "$IDENTITY_HOME"
if [ -d "$CARGO_PATH/keys" ]; then
  cp "$CARGO_PATH/keys/"* "$IDENTITY_HOME/"
  echo "Copied proving.key & verification.key to '$IDENTITY_HOME'."
else
  echo "Warning: keys/ directory not found in project root; please copy your keys manually." >&2
fi

# 4. Create .desktop entry for custom protocol
echo "Registering 'identity://' protocol handler..."
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=Identity Prover
Exec=$IDENTITY_BIN %u
Type=Application
Terminal=true
MimeType=x-scheme-handler/identity;
EOF

# 5. Update MIME database and protocol association
xdg-mime default $(basename "$DESKTOP_FILE") x-scheme-handler/identity
update-desktop-database "$DESKTOP_DIR"

echo "Protocol handler registered successfully."

# 6. Final message
cat <<EOF

Installation complete!

• Place your 'identity.json' in '$IDENTITY_HOME' and you’re ready to go.
• Test by opening: xdg-open "identity://verify?origin=https://example.com&dob_before=726632&license=2"
EOF

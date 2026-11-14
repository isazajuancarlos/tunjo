#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Regenera el verificador WASM de la página (sitio/verificador/) DESDE LA FUENTE.
# Todo sale del vendor/ del repo (offline, reproducible); lo único externo es la
# herramienta `wasm-bindgen-cli`, que debe coincidir con la version de la crate
# `wasm-bindgen` del Cargo.lock:
#
#     cargo install wasm-bindgen-cli --version <la del lock> --locked
#
# El positivo de control de reproducibilidad offline (CARGO_HOME vacío), como el
# resto del repo:  CH=$(mktemp -d); CARGO_HOME=$CH cargo build --release; rm -rf $CH
set -euo pipefail
cd "$(dirname "$0")"                       # verificador-wasm/
raiz="$(cd .. && pwd)"                      # tunjo/

# `cargo install` deja wasm-bindgen en ~/.cargo/bin, que NO está en el PATH del
# shell no interactivo del despliegue. Sin esto, la línea de abajo moría con 127
# bajo `set -euo pipefail` ANTES de llegar al mensaje útil (medido 2026-10-18).
export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"

esperada="$(grep -A1 '^name = "wasm-bindgen"$' "$raiz/Cargo.lock" | grep version | head -1 | sed 's/[^0-9.]//g')"
# `|| true`: si wasm-bindgen NO está, `tiene` queda vacío y cae en el `if` con el
# mensaje de «instala la que toca», en vez de abortar con un 127 opaco (pipefail).
tiene="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || true)"
if [ "$tiene" != "$esperada" ]; then
  echo "wasm-bindgen-cli $tiene != $esperada (la del lock). Instala la que toca:" >&2
  echo "  cargo install wasm-bindgen-cli --version $esperada --locked" >&2
  exit 1
fi

# Compila a wasm32 (el .cargo/config de este crate fija el target y el cfg de
# getrandom; las deps salen del vendor/ compartido del workspace).
cargo build --release
wasm-bindgen "$raiz/target/wasm32-unknown-unknown/release/verificador_wasm.wasm" \
  --out-dir "$raiz/sitio/verificador" --target web

echo "OK -> sitio/verificador/ (verificador_wasm.js + verificador_wasm_bg.wasm)"

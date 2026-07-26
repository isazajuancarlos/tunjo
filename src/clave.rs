// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! La clave del perito.
//!
//! Se guarda cifrada con el propio contenedor de Quipu (Argon2id +
//! ChaCha20-Poly1305). Una clave de firma forense en claro sobre el disco es
//! la primera cosa que la contraparte usaría para negar la autoría del acta:
//! si cualquiera con acceso al portátil pudo firmar, el sello no prueba quién.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use quipu::api::{Options, decode_from_blob, encode_to_blob};
use quipu::pqsign::{TripleSigningKey, TripleVerifyingKey, generate_triple_keypair};

/// Marca del archivo de clave. Sale como huella del codebook, así que un
/// archivo que no sea una clave de tunjo falla antes de pedir la contraseña.
const HUELLA: [u8; 8] = *b"TUNJOKEY";

/// Genera un par nuevo y deja la clave privada cifrada en `ruta`.
pub fn generar(ruta: &Path, passphrase: &str) -> Result<TripleVerifyingKey> {
    if ruta.exists() {
        // Sobrescribir una clave de firma es irreversible y deja sin verificar
        // todas las actas firmadas con ella. No se hace nunca en silencio.
        bail!(
            "ya existe {} — no se sobrescribe una clave de firma: las actas \
             firmadas con ella quedarían sin poder verificarse",
            ruta.display()
        );
    }
    let (vk, sk) = generate_triple_keypair();
    let blob = encode_to_blob(&sk.to_bytes(), passphrase, HUELLA, &Options::default());
    fs::write(ruta, &blob).with_context(|| format!("escribiendo {}", ruta.display()))?;
    restringir_permisos(ruta)?;
    Ok(vk)
}

/// Carga y descifra la clave de firma.
pub fn cargar(ruta: &Path, passphrase: &str) -> Result<TripleSigningKey> {
    let blob = fs::read(ruta).with_context(|| format!("leyendo {}", ruta.display()))?;
    let bytes = decode_from_blob(&blob, passphrase, HUELLA, b"")
        .map_err(|e| anyhow::anyhow!("no se pudo abrir la clave ({e:?}): ¿contraseña correcta?"))?;
    TripleSigningKey::from_bytes(&bytes)
        .ok_or_else(|| anyhow::anyhow!("el archivo no contiene una clave de firma triple válida"))
}

#[cfg(unix)]
fn restringir_permisos(ruta: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(ruta, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restringir_permisos(_ruta: &Path) -> Result<()> {
    // En Windows el archivo hereda la ACL del directorio del usuario. El
    // cifrado del contenedor es lo que protege la clave, no los permisos.
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn ciclo_completo_de_clave() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        let vk = generar(&ruta, "contraseña larga de prueba").unwrap();
        let sk = cargar(&ruta, "contraseña larga de prueba").unwrap();
        let firma = sk.sign(b"acta");
        assert!(vk.verify(b"acta", &firma));
        assert_eq!(sk.verifying_key().to_bytes(), vk.to_bytes());
    }

    #[test]
    fn contrasena_equivocada_no_abre_la_clave() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        generar(&ruta, "la buena").unwrap();
        assert!(cargar(&ruta, "la mala").is_err());
    }

    #[test]
    fn no_se_sobrescribe_una_clave_existente() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        generar(&ruta, "una").unwrap();
        let antes = fs::read(&ruta).unwrap();
        assert!(generar(&ruta, "otra").is_err());
        assert_eq!(antes, fs::read(&ruta).unwrap(), "la clave original se conserva intacta");
    }

    #[test]
    fn la_clave_no_queda_en_claro_en_el_archivo() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        generar(&ruta, "contraseña").unwrap();
        let sk = cargar(&ruta, "contraseña").unwrap();
        let en_disco = fs::read(&ruta).unwrap();
        let secreto = sk.to_bytes();
        assert!(
            !en_disco.windows(secreto.len()).any(|v| v == secreto.as_slice()),
            "el material secreto aparece literalmente en el archivo"
        );
    }
}

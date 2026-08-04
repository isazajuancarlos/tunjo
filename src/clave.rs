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
    let bytes = decode_from_blob(&blob, passphrase, HUELLA, b"").map_err(|e| motivo(e, ruta))?;
    TripleSigningKey::from_bytes(&bytes)
        .ok_or_else(|| anyhow::anyhow!("el archivo no contiene una clave de firma triple válida"))
}

/// Traduce el fallo del contenedor al motivo REAL, que no siempre es la
/// contraseña.
///
/// Hasta el 2026-08-04 todo error de `decode_from_blob` salía como
/// «no se pudo abrir la clave (…): ¿contraseña correcta?». A quien apuntaba al
/// archivo equivocado —lo más fácil de hacer con `--ruta`— se le mandaba a
/// revisar una contraseña que estaba bien, y el contenedor ni siquiera había
/// llegado a probarla: `CodebookMismatch` se decide comparando la huella de la
/// cabecera, ANTES del KDF. Es la misma regla que el resto de la herramienta:
/// no se afirma lo que no se comprobó.
///
/// El `match` es exhaustivo a propósito, sin brazo comodín: si Quipu añade una
/// variante, esto deja de compilar en vez de heredar un mensaje que miente.
fn motivo(e: quipu::api::DecodeError, ruta: &Path) -> anyhow::Error {
    use quipu::api::DecodeError as D;
    use quipu::container::ContainerError as C;

    let r = ruta.display();
    match e {
        D::Container(C::TooShort | C::BadMagic) => anyhow::anyhow!(
            "{r} no es una clave de tunjo: no lleva la cabecera del contenedor \
             cifrado. La contraseña no se llegó a probar — comprueba la ruta"
        ),
        D::Container(C::UnsupportedVersion(v)) => anyhow::anyhow!(
            "{r} usa la versión {v} del contenedor y esta copia de tunjo no la \
             conoce. Hace falta una versión más nueva: no se intenta adivinar el \
             formato"
        ),
        D::Container(C::FlagsDesconocidos(f)) => anyhow::anyhow!(
            "{r} trae marcas de formato que esta copia de tunjo no conoce \
             ({f:#010b}). Se rechaza en vez de interpretarlo con las reglas \
             viejas, que daría un resultado mal leído con el cifrado en verde"
        ),
        D::CodebookMismatch => anyhow::anyhow!(
            "{r} es un contenedor cifrado de Quipu, pero NO una clave de tunjo: \
             le falta la marca {}. La contraseña no se llegó a probar",
            String::from_utf8_lossy(&HUELLA)
        ),
        D::Decrypt => anyhow::anyhow!(
            "no se pudo descifrar {r}: la contraseña es incorrecta, o el archivo \
             fue alterado. Las dos cosas fallan igual y desde aquí no se pueden \
             distinguir"
        ),
        // Los dos caminos del diccionario y de la firma no los recorre una clave
        // de perito, que va por blob y por contraseña. Si aparecen, lo honrado es
        // decir que no sabemos, no elegir la explicación más cómoda.
        e @ (D::Symbol(_) | D::BadSignature) => anyhow::anyhow!(
            "{r} falló al abrirse con un error que este camino no debería \
             producir ({e:?}); no se interpreta"
        ),
    }
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

    // Los tres de abajo van juntos y se validan entre sí: dos que NO pueden
    // culpar a la contraseña y uno que TIENE que culparla. Con los primeros
    // solos pasaría igual un mensaje que nunca la nombra; con el último solo,
    // el que la nombra siempre —que es justo el que había hasta hoy—.

    /// El mensaje de un `cargar` que debía fallar.
    ///
    /// No se usa `unwrap_err()` porque exige `Debug` en el lado bueno, y
    /// `TripleSigningKey` no lo implementa a propósito: una clave privada no
    /// tiene por qué poder imprimirse. La prueba se adapta al tipo, no al revés.
    fn error_de(r: Result<TripleSigningKey>) -> String {
        match r {
            Ok(_) => panic!("esto tenía que fallar y abrió la clave"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn un_archivo_que_no_es_contenedor_no_culpa_a_la_contrasena() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("cualquiera.bin");
        fs::write(&ruta, [0xAB; 4096]).unwrap();

        let e = error_de(cargar(&ruta, "da igual"));
        assert!(e.contains("no es una clave de tunjo"), "{e}");
        assert!(
            !e.contains("contraseña es incorrecta"),
            "no se puede mandar a revisar la contraseña: ni se probó — {e}"
        );
    }

    #[test]
    fn un_contenedor_de_quipu_que_no_es_clave_de_tunjo_se_distingue() {
        // La pareja exacta del anterior: contenedor BIEN FORMADO, con su
        // cabecera y su cifrado, del que solo cambia la marca. Si el mensaje se
        // apoyara en la forma del archivo y no en la huella, aquí se caería.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("otro.blob");
        let ajena = *b"OTRACOSA";
        assert_ne!(ajena, HUELLA, "la marca ajena tiene que ser distinta");
        let blob = encode_to_blob(b"contenido cualquiera", "la buena", ajena, &Options::default());
        fs::write(&ruta, &blob).unwrap();

        let e = error_de(cargar(&ruta, "la buena"));
        assert!(e.contains("NO una clave de tunjo"), "{e}");
        assert!(e.contains("TUNJOKEY"), "dice qué marca falta — {e}");
        assert!(
            !e.contains("contraseña es incorrecta"),
            "la contraseña era la BUENA y ni se llegó a probar — {e}"
        );
    }

    #[test]
    fn la_contrasena_equivocada_si_nombra_la_contrasena() {
        // El control positivo. Sin él, «no culpa a la contraseña» lo cumpliría
        // un mensaje que no la nombra nunca, y el caso real quedaría mudo.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        generar(&ruta, "la buena").unwrap();

        let e = error_de(cargar(&ruta, "la mala"));
        assert!(e.contains("contraseña es incorrecta"), "{e}");
        assert!(
            e.contains("alterado"),
            "y no se afirma cuál de las dos fue: desde aquí no se distinguen — {e}"
        );
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

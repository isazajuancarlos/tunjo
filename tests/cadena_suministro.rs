// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! El guardián de la única exención de `cargo-deny`.
//!
//! # Por qué existe
//!
//! `deny.toml` silencia RUSTSEC-2023-0071 —el «Marvin Attack» sobre el crate
//! `rsa`— con un argumento que es cierto HOY: tunjo no tiene ninguna clave privada
//! RSA. Usa `rsa` en un solo sitio y solo para VERIFICAR la firma de un token de
//! sellado con la clave PÚBLICA de la autoridad, y la vulnerabilidad es una fuga
//! por tiempo de las operaciones con la clave privada.
//!
//! Pero un `ignore` en un archivo de configuración es **un atajo que evita una
//! comprobación**, y a eso se le exige lo mismo que a cualquier otra salvaguarda:
//! que discrimine. Un argumento escrito en un comentario envejece en silencio; el
//! día que alguien meta una firma RSA de verdad, el comentario seguirá ahí diciendo
//! que no hay claves privadas y el aviso seguirá silenciado.
//!
//! Así que la premisa se comprueba en vez de confiarse. Estas pruebas se ponen
//! rojas el día que deje de ser verdad lo que `deny.toml` afirma.

use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Todos los `.rs` de `src/`, que es donde vive el código de tunjo.
fn fuentes(dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir).expect("src/ tiene que existir") {
        let ruta = e.expect("entrada legible").path();
        if ruta.is_dir() {
            v.extend(fuentes(&ruta));
        } else if ruta.extension().is_some_and(|x| x == "rs") {
            v.push(ruta);
        }
    }
    assert!(!v.is_empty(), "no se encontró ningún .rs: la prueba no estaría mirando nada");
    v
}

/// La premisa de la exención: **no existe ninguna clave privada RSA en tunjo**.
///
/// `RsaPrivateKey` es el cuello de botella del crate: firmar y descifrar exigen
/// una, así que basta con que ese nombre no aparezca. Si algún día hace falta —una
/// firma RSA propia, un descifrado— esta prueba se pone roja y obliga a revisar la
/// exención antes que el código, que es el orden correcto: primero se comprueba la
/// premisa y después el funcionamiento.
#[test]
fn la_exencion_de_rsa_sigue_siendo_cierta() {
    let mut culpables = Vec::new();
    for ruta in fuentes(&repo().join("src")) {
        let texto = fs::read_to_string(&ruta).expect("fuente legible");
        if texto.contains("RsaPrivateKey") {
            culpables.push(ruta.display().to_string());
        }
    }
    assert!(
        culpables.is_empty(),
        "aparece una clave privada RSA en {culpables:?}.\n\
         La exención de RUSTSEC-2023-0071 en deny.toml se apoya en que NO la hay: la \
         vulnerabilidad es una fuga por tiempo de las operaciones con la clave privada. \
         Si ahora sí se usa, hay que quitar el `ignore` y afrontar el aviso, no ampliar \
         el argumento."
    );
}

/// Y que la exención siga siendo UNA, y esa.
///
/// Un `ignore` se amplía con una línea y sin que nadie lo mire. Fijar la lista
/// completa obliga a que añadir un aviso silenciado sea un acto deliberado, con su
/// justificación y su guardián, como lo fue este.
#[test]
fn no_hay_mas_avisos_silenciados_que_el_que_esta_justificado() {
    let deny = fs::read_to_string(repo().join("deny.toml")).expect("deny.toml legible");
    let linea = deny
        .lines()
        .find(|l| l.trim_start().starts_with("ignore"))
        .expect("deny.toml tiene que llevar su lista de exenciones, aunque sea vacía");
    assert_eq!(
        linea.trim(),
        r#"ignore = ["RUSTSEC-2023-0071"]"#,
        "cambió la lista de avisos silenciados. Cada uno necesita su argumento escrito \
         y su prueba de que la premisa sigue siendo cierta — como la tiene RUSTSEC-2023-0071 \
         en `la_exencion_de_rsa_sigue_siendo_cierta`."
    );
}

/// Y que la premisa se pueda romper de verdad: el detector tiene que distinguir.
///
/// Una prueba que busca un nombre en un archivo pasa igual si mira el archivo
/// equivocado o si el patrón nunca casa con nada. Aquí se le da el caso que DEBERÍA
/// ponerla roja y se comprueba que reacciona.
#[test]
fn el_detector_discrimina() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("src")).unwrap();
    fs::write(
        dir.path().join("src/culpable.rs"),
        "let sk = RsaPrivateKey::from_pkcs8_der(bytes)?;",
    )
    .unwrap();

    let encontrado = fuentes(&dir.path().join("src"))
        .iter()
        .any(|r| fs::read_to_string(r).unwrap().contains("RsaPrivateKey"));
    assert!(encontrado, "el detector no ve una clave privada RSA puesta a propósito");
}

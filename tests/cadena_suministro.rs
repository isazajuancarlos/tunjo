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


// ---------------------------------------------------------------------------
// El otro atajo que evita una comprobación: los `ignore` de Dependabot.
// ---------------------------------------------------------------------------

/// El racimo ASN.1 se ignora en `dependabot.yml` con un argumento que también es
/// cierto HOY: `cms` 0.2 fija `const-oid ^0.9.4`, `der ^0.7.7`, `spki ^0.7` y
/// `x509-cert ^0.2.3`, así que subir uno solo mete dos pilas ASN.1 en el binario.
/// Es la misma clase de atajo que la exención de `deny.toml`, y se le exige lo
/// mismo: que discrimine.
///
/// **Los comentarios se quitan antes de mirar**, y no es un detalle. La primera
/// versión de estas pruebas buscaba la cadena `target-branch` en el archivo
/// entero y se puso roja por el comentario que explica **por qué no se pone** —
/// un detector que confunde la prosa con la configuración. La regla se arregló
/// en la regla, no tapando el caso (directiva 23).
fn dependabot_sin_comentarios() -> String {
    let bruto = fs::read_to_string(repo().join(".github/dependabot.yml"))
        .expect(".github/dependabot.yml tiene que existir");
    sin_comentarios(&bruto)
}

/// Quita comentarios de un YAML. No hay cadenas con `#` en este archivo, así que
/// cortar por el primer `#` de cada línea basta y no necesita un analizador.
fn sin_comentarios(y: &str) -> String {
    y.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

/// `cms` NUNCA se ignora: es quien manda en el racimo, y su 0.3 estable es la
/// señal de que ya se puede mover. Ignorarlo sería un vigilante que se calla
/// justo el único evento que importa.
#[test]
fn el_crate_que_manda_en_el_racimo_no_esta_silenciado() {
    assert!(
        !dependabot_sin_comentarios().contains("dependency-name: cms"),
        "`cms` aparece en los ignore: el día que salga su 0.3 estable —lo único \
         que desbloquea el racimo ASN.1— no se enteraría nadie"
    );
}

/// Los PARCHES siguen entrando. Ahí es donde aterrizan los arreglos de seguridad
/// dentro de una línea fijada; bloquearlos sería el sesgo a cerrar (directiva 21).
#[test]
fn los_parches_no_estan_silenciados() {
    assert!(
        !dependabot_sin_comentarios().contains("version-update:semver-patch"),
        "algún ignore bloquea parches, que es por donde llegan los arreglos de \
         seguridad de una línea fijada"
    );
}

/// `target-branch` desconecta esa entrada de las actualizaciones de SEGURIDAD.
/// Es la clave que apaga las alertas sin dar ningún error.
#[test]
fn ninguna_entrada_lleva_target_branch() {
    assert!(
        !dependabot_sin_comentarios().contains("target-branch"),
        "`target-branch` desconecta esa entrada de las actualizaciones de seguridad"
    );
}

/// Y que las tres discriminen, con las DOS parejas que hacen falta.
///
/// El caso rojo: un archivo que trae las tres cosas prohibidas, y que las tres
/// comprobaciones tienen que ver. El caso que NO debe disparar: exactamente esas
/// tres palabras dentro de comentarios, que es el falso positivo real que tuvo
/// esta prueba antes de quitarlos — con el detector viejo salía roja.
#[test]
fn el_detector_de_dependabot_discrimina() {
    let malo = sin_comentarios(concat!(
        "updates:\n",
        "  - package-ecosystem: cargo\n",
        "    target-branch: main\n",
        "    ignore:\n",
        "      - dependency-name: cms\n",
        "        update-types: [version-update:semver-patch]\n",
    ));
    assert!(malo.contains("target-branch"), "no ve un target-branch puesto a propósito");
    assert!(malo.contains("dependency-name: cms"), "no ve a `cms` silenciado");
    assert!(malo.contains("version-update:semver-patch"), "no ve un parche bloqueado");

    let solo_prosa = sin_comentarios(
        "# NUNCA se pone `target-branch`, y `dependency-name: cms` no se ignora\n\
         # porque los `version-update:semver-patch` tienen que seguir entrando.\n\
         version: 2\n",
    );
    assert!(
        !solo_prosa.contains("target-branch")
            && !solo_prosa.contains("dependency-name: cms")
            && !solo_prosa.contains("version-update:semver-patch"),
        "el detector confunde un comentario con configuración: es el falso \
         positivo que ya tuvo una vez"
    );
}

// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verificador de actas de tunjo para el navegador (wasm32).
//!
//! Reusa la MISMA verificación del binario (`Acta::verificar_sello` +
//! `verificar_sello_tiempo`): integridad por raíz de Merkle recalculada, firma
//! triple-híbrida y —si el acta lo trae— el token RFC 3161 del sello de tiempo. El
//! cotejo del CONTENIDO de cada archivo lo hace el navegador recomputando su SHA-256
//! con [`sha256_hex`] y comparándolo con el que el acta declara — igual que `--origen`
//! en el binario, pero sin leer disco: los bytes llegan del archivo que el usuario
//! arrastra.
//!
//! **Qué acredita y qué NO.** `ok` dice que la raíz y la firma son consistentes con la
//! clave pública que el PROPIO acta trae — no que el firmante sea quien dice ser. La
//! firma es electrónica (Decreto 2364/2012): acredita integridad y autoría respecto de
//! ESA clave, y la identidad del perito se establece comparando la huella de su clave
//! (`huella_clave`) con la que el perito publicó por un canal aparte. Por eso el
//! veredicto nunca afirma «nadie la alteró» a secas (invariante 9: acredita, no
//! concluye).
//!
//! Nada sale de la máquina del usuario: todo corre en su navegador.

use sha2::{Digest, Sha256};
use tunjo::acta::{Acta, ErrorActa};
use tunjo::texto::plano;
use wasm_bindgen::prelude::*;

fn a_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// SHA-256 en hexadecimal de unos bytes. El navegador lo llama por cada archivo
/// arrastrado para compararlo con el que el acta declara.
#[wasm_bindgen]
pub fn sha256_hex(bytes: &[u8]) -> String {
    a_hex(&Sha256::digest(bytes))
}

/// Verifica el acta y devuelve un veredicto en JSON:
/// ```json
/// {ok, mensaje, referencia, perito, huella_clave, raiz, sello:{estado, mensaje, fecha},
///  elementos:[{ruta, sha256, estado, metodo_huella, cotejable}]}
/// ```
///
/// - `ok`: la raíz y la firma triple son consistentes con la clave pública que trae el
///   acta (integridad + autoría respecto de ESA clave, invariante 9). No prueba la
///   identidad del perito: eso lo cierra comparar `huella_clave` con la publicada.
/// - `sello`: el estado REAL del token RFC 3161 (`ausente` / `sin_anclar` / `invalido`).
///   El binario verifica el token; el navegador no puede quedarse corto sin divergir
///   del binario (invariante 3). Sin `--tsa-ca` no hay ancla posible en el navegador,
///   así que un token válido es «sin anclar»: fecha consistente pero no «fecha cierta».
/// - `cotejable`: `false` cuando el elemento no trae SHA-256 que recomputar (se registró
///   «leído sin huella», o su estado no es un elemento sellado normal). El cotejo de cada
///   archivo contra su `sha256` lo cierra el navegador con `sha256_hex`.
#[wasm_bindgen]
pub fn verificar_acta(acta_json: &[u8]) -> String {
    let acta: Acta = match serde_json::from_slice(acta_json) {
        Ok(a) => a,
        Err(e) => {
            return serde_json::json!({
                "ok": false,
                // El mensaje de error de serde puede arrastrar fragmentos del JSON ajeno;
                // se neutraliza como cualquier texto que vaya a pantalla (invariante 2).
                "mensaje": plano(&format!("El archivo no es un acta de tunjo válida: {e}")),
                "elementos": []
            })
            .to_string();
        }
    };

    let firma_ok = acta.verificar_sello();

    // H1 (concilio 2026-10-12): el navegador DEBE verificar el token RFC 3161 igual que
    // el binario, o un token ajeno/basura se vería como «sello presente» con el acta en
    // verde (divergencia, invariante 3). Sin `--tsa-ca` no hay anclas en el navegador, así
    // que lo más que un token válido acredita es `SinAnclar`: fecha consistente, no cierta.
    let sello_res = acta.verificar_sello_tiempo(&[]);
    let sello_invalido = sello_res.is_err();
    let sello = match &sello_res {
        Ok(None) => serde_json::json!({
            "estado": "ausente",
            "mensaje": "El acta no trae sello de tiempo RFC 3161.",
        }),
        Ok(Some((datos, _confianza))) => serde_json::json!({
            "estado": "sin_anclar",
            // `fecha_utc` sale de un DateTime (seguro por su forma, como en main.rs); aun
            // así se neutraliza por si una autoridad metiera texto raro en el campo.
            "fecha": plano(&datos.fecha_utc),
            "mensaje": "Token RFC 3161 válido, pero SIN ANCLAR: la fecha es consistente, \
                        no es «fecha cierta». Para exigir ancla, verifíquela con el binario \
                        y --tsa-ca.",
        }),
        Err(e) => serde_json::json!({
            "estado": "invalido",
            "mensaje": plano(&format!("El sello de tiempo NO verifica: {e}")),
        }),
    };

    // `ok` replica EXACTAMENTE el veredicto del binario (main.rs: `verificada.valida
    // && !sello.invalido`): un sello presente-pero-INVÁLIDO tumba el veredicto aunque
    // la firma y la raíz estén intactas. Sin esto, un acta con token basura se vería
    // verde en la web y el binario la rechazaría con exit 1 (divergencia, invariante 3).
    // Tres estados, no dos: «conforme», «no_conforme» (verificó y FALLÓ) y
    // «no_verificable» (no se pudo verificar porque este binario no conoce la versión
    // del acta). Colapsar el tercero en «no_conforme» repetía en la web el residuo que
    // la negociación de versión cierra en el CLI: un acta de una versión futura se vería
    // como «NO verifica» (forjada) cuando lo honesto es «no sé leer esta versión». El
    // CLI lo trata como error de operación (código 2); la web le da su propio estado.
    let (ok, estado, mensaje) = match (&firma_ok, sello_invalido) {
        (Ok(()), false) => (
            true,
            "conforme",
            "La raíz de integridad y la firma triple son consistentes con la clave que trae el acta."
                .to_string(),
        ),
        (Ok(()), true) => (
            false,
            "no_conforme",
            "La firma verifica, pero el SELLO DE TIEMPO no: el acta NO está conforme.".to_string(),
        ),
        // Versión que este verificador no conoce: no se afirma nada sobre autenticidad.
        // El `Display` de estos errores ya viene saneado (invariante 2), pero se pasa por
        // `plano` igual, como el resto de la salida.
        (Err(e @ (ErrorActa::VersionNoSoportada { .. } | ErrorActa::FormatoDesconocido(_))), _) => {
            (false, "no_verificable", plano(&e.to_string()))
        }
        (Err(e), _) => (false, "no_conforme", plano(&format!("El acta NO verifica: {e}"))),
    };

    let elementos: Vec<serde_json::Value> = acta
        .elementos
        .iter()
        .map(|el| {
            // H2 (concilio): `ruta`, `estado` y `metodo_huella` son texto que vino del
            // disco del perito y va a la pantalla del juez → `plano` (invariante 2). El
            // `sha256` es hex por construcción; se deja crudo (como en main.rs).
            serde_json::json!({
                "ruta": plano(&el.ruta),
                "sha256": el.sha256,
                "estado": plano(&el.estado),
                "metodo_huella": plano(&el.metodo_huella),
                // Sin SHA-256 no hay nada que recomputar en el navegador (p.ej. «leído sin
                // huella»): el navegador lo marca «no cotejable aquí» en vez de fingir cotejo.
                "cotejable": !el.sha256.is_empty(),
            })
        })
        .collect();

    serde_json::json!({
        "ok": ok,
        // «conforme» | «no_conforme» | «no_verificable». `ok` se mantiene (compat), pero
        // la página distingue por `estado`: «no_verificable» NO es un veredicto de forja.
        "estado": estado,
        "mensaje": mensaje,
        // H2: referencia y perito llegan de texto libre del acta → neutralizados.
        "referencia": plano(&acta.caso.referencia),
        "perito": plano(&acta.perito.nombre),
        // H3 (concilio): la huella de la clave pública del perito. La página la muestra
        // para que se compare con la que el perito publicó: así «autoría respecto de esta
        // clave» se vuelve «autoría de ESTE perito», que es lo que la firma sola NO prueba
        // (la clave viaja DENTRO del acta y cualquiera puede forjar una). Se usa la MISMA
        // función que el acta legible (`informe::huella`): SHA-256 de los bytes decodificados
        // de la clave, en grupos — así la huella de la web y la del dictamen son idénticas y
        // se cotejan carácter a carácter. Es dígitos/espacios, forma segura; no pasa por plano.
        "huella_clave": tunjo::informe::huella(&acta.perito.clave_publica),
        // Paso 5 del concilio: con `ok:false` por raíz/firma, `raiz_merkle` es texto ajeno
        // arbitrario y va a pantalla → `plano` como el resto (invariante 2, sin crudos).
        "raiz": plano(&acta.raiz_merkle),
        "sello": sello,
        "elementos": elementos,
    })
    .to_string()
}

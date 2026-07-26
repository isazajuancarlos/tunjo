// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! El acta en la forma en que se anexa a un dictamen: legible por un juez.
//!
//! El JSON es lo que se firma y lo que se verifica; este documento es lo que se
//! lee. Por eso se genera SIEMPRE desde el JSON y nunca al revés: si alguien
//! edita el Markdown, el sello sigue estando sobre el JSON y la diferencia se
//! nota.

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use crate::acta::{Acta, hex};

fn escapar(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// Huella legible de un valor en base64.
///
/// La clave pública triple ocupa 3,5 KB en base64 y la firma ronda los 46 KB:
/// impresos ocupan cientos de páginas y nadie los coteja a ojo. En el documento
/// va la huella —que sí se compara de un vistazo— y el valor íntegro queda en el
/// JSON, que es lo que verifica la máquina. El acta lo dice expresamente para
/// que nadie crea que el papel basta para verificar.
fn huella(b64: &str) -> String {
    let bytes = match STANDARD.decode(b64) {
        Ok(b) => b,
        Err(_) => return "(valor ilegible)".into(),
    };
    let h = hex(&Sha256::digest(&bytes));
    let grupos: Vec<String> = h.as_bytes().chunks(8).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    format!("{} ({} bytes)", grupos.join(" "), bytes.len())
}

pub fn markdown(acta: &Acta) -> String {
    let mut m = String::new();
    let leidos = acta.elementos.iter().filter(|e| e.estado == "leido").count();
    let errores: Vec<_> = acta.elementos.iter().filter(|e| e.estado.starts_with("ERROR")).collect();
    let bytes: u64 = acta.elementos.iter().map(|e| e.bytes).sum();

    m.push_str("# Acta de sellado de evidencia digital\n\n");
    m.push_str(&format!("**Referencia:** {}\n\n", acta.caso.referencia));
    m.push_str(&format!("{}\n\n", acta.caso.descripcion));

    m.push_str("## 1. Perito\n\n");
    m.push_str(&format!("- **Nombre:** {}\n", acta.perito.nombre));
    m.push_str(&format!("- **Identificación:** {}\n", acta.perito.identificacion));
    m.push_str(&format!(
        "- **Clave pública de verificación** — huella SHA-256:\n\n```\n{}\n```\n\n",
        huella(&acta.perito.clave_publica)
    ));

    m.push_str("## 2. Método de adquisición\n\n");
    m.push_str(&format!("- **Origen:** `{}`\n", acta.adquisicion.origen));
    m.push_str(&format!("- **Método:** {}\n", acta.adquisicion.metodo));
    m.push_str(&format!("- **Herramienta:** {}\n", acta.adquisicion.herramienta));
    m.push_str(&format!("- **Algoritmos:** {}\n", acta.adquisicion.algoritmos));
    m.push_str("- **Acceso:** exclusivamente de lectura. La herramienta no escribe dentro del origen.\n\n");

    m.push_str("### Registro horario\n\n");
    m.push_str(&format!("- **Inicio (UTC):** {}\n", acta.adquisicion.reloj.inicio_utc));
    m.push_str(&format!("- **Fin (UTC):** {}\n", acta.adquisicion.reloj.fin_utc));
    m.push_str(&format!("- **Desfase local respecto de UTC:** {}\n", acta.adquisicion.reloj.desfase_local_utc));
    m.push_str(&format!("- **Contraste del reloj:** {}\n\n", acta.adquisicion.reloj.verificacion));

    m.push_str("## 3. Resumen\n\n");
    m.push_str(&format!("| Elementos | Leídos | Ilegibles | Bytes |\n|---|---|---|---|\n"));
    m.push_str(&format!(
        "| {} | {} | {} | {} |\n\n",
        acta.elementos.len(),
        leidos,
        errores.len(),
        bytes
    ));

    if !errores.is_empty() {
        m.push_str("> **Elementos que no pudieron leerse.** Constan en el acta y NO están\n");
        m.push_str("> cubiertos por una afirmación de integridad: de ellos solo se acredita\n");
        m.push_str("> que existían y que la lectura falló.\n\n");
        for e in &errores {
            m.push_str(&format!("> - `{}` — {}\n", escapar(&e.ruta), escapar(&e.estado)));
        }
        m.push('\n');
    }

    m.push_str("## 4. Raíz de integridad\n\n");
    m.push_str("Raíz del árbol de Merkle construido sobre los elementos listados en el\n");
    m.push_str("anexo. Cualquier cambio en un byte, en una ruta o en el orden produce una\n");
    m.push_str("raíz distinta.\n\n");
    m.push_str(&format!("```\n{}\n```\n\n", acta.raiz_merkle));

    m.push_str("## 5. Firma\n\n");
    match &acta.firma {
        Some(f) => {
            m.push_str(&format!("- **Algoritmo:** {}\n", f.algoritmo));
            m.push_str("- **Cobertura:** la totalidad del acta en formato JSON, incluidos el\n");
            m.push_str("  listado de elementos y la raíz.\n\n");
            m.push_str("Huella SHA-256 de la firma:\n\n");
            m.push_str(&format!("```\n{}\n```\n\n", huella(&f.valor)));
            m.push_str("> La firma y la clave completas están en el archivo JSON, no en este\n");
            m.push_str("> documento: impresas ocuparían cientos de páginas que nadie cotejaría.\n");
            m.push_str("> **La verificación se hace sobre el JSON**; este documento es para leer,\n");
            m.push_str("> no para verificar.\n\n");
        }
        None => m.push_str("**ACTA SIN FIRMAR.** No acredita nada mientras no se selle.\n\n"),
    }

    m.push_str("## 6. Cómo verificar esta acta\n\n");
    m.push_str("Cualquier tercero puede comprobarla sin intervención del perito y sin\n");
    m.push_str("software propietario: el verificador es libre y su código es público.\n\n");
    m.push_str("```bash\ntunjo verificar acta.json                 # firma y coherencia interna\ntunjo verificar acta.json --origen RUTA   # además, contra el material en disco\n```\n\n");

    m.push_str("## 7. Alcance y límites\n\n");
    m.push_str("Se deja constancia expresa de lo que esta acta **no** dice:\n\n");
    m.push_str("1. Acredita que los elementos listados tenían exactamente ese contenido en\n");
    m.push_str("   el momento de la adquisición, y que no han cambiado desde entonces.\n");
    m.push_str("2. **No** acredita qué contenía el material antes de la intervención del\n");
    m.push_str("   perito, ni quién lo creó, ni si fue alterado con anterioridad.\n");
    m.push_str("3. **No** contiene conclusión alguna sobre intrusiones, autoría o\n");
    m.push_str("   responsabilidad. Eso corresponde al dictamen, no a la herramienta.\n");
    m.push_str("4. La fecha registrada es la del reloj de la máquina, contrastada según se\n");
    m.push_str("   indica en el numeral 2. Sin sello de tiempo de tercero, prueba orden\n");
    m.push_str("   relativo, no fecha cierta oponible.\n\n");

    m.push_str("## 8. Fundamento normativo\n\n");
    m.push_str("- **Ley 527 de 1999, arts. 8 a 11.** Un mensaje de datos es íntegro si ha\n");
    m.push_str("  permanecido completo e inalterado; su fuerza probatoria se valora según\n");
    m.push_str("  la confiabilidad de la forma en que se generó, archivó o comunicó, la\n");
    m.push_str("  forma en que se conservó su integridad y la identificación de su\n");
    m.push_str("  iniciador. Los tres extremos son, exactamente, lo que esta acta documenta.\n");
    m.push_str("- **CGP (Ley 1564 de 2012), art. 247.** Los mensajes de datos se valoran en\n");
    m.push_str("  el formato en que fueron generados; de ahí que se sellen los archivos\n");
    m.push_str("  originales y no una impresión.\n");
    m.push_str("- **CGP, art. 226.** El dictamen debe ser claro, preciso, exhaustivo y\n");
    m.push_str("  detallado, y explicar los exámenes, métodos e investigaciones efectuados.\n");
    m.push_str("  Esta acta es el soporte metodológico de esa exigencia.\n");
    m.push_str("- **CPP (Ley 906 de 2004), art. 254.** Factores de la cadena de custodia:\n");
    m.push_str("  identidad, estado original, condiciones de recolección, preservación,\n");
    m.push_str("  embalaje y envío; lugares y fechas de permanencia y los cambios que cada\n");
    m.push_str("  custodio realizó.\n\n");
    m.push_str("Ver `MARCO_JURIDICO.md` para el detalle y las fuentes.\n\n");

    m.push_str("## Anexo. Elementos\n\n");
    m.push_str("| # | Ruta | Tipo | Bytes | SHA-256 | Modificado (UTC) | Estado |\n");
    m.push_str("|---|---|---|---|---|---|---|\n");
    for (i, e) in acta.elementos.iter().enumerate() {
        m.push_str(&format!(
            "| {} | `{}` | {} | {} | `{}` | {} | {} |\n",
            i + 1,
            escapar(&e.ruta),
            e.tipo,
            e.bytes,
            if e.sha256.is_empty() { "—" } else { &e.sha256 },
            if e.modificado_utc.is_empty() { "—" } else { &e.modificado_utc },
            escapar(&e.estado),
        ));
    }
    m
}

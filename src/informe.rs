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

/// Neutraliza una cadena que viene del JSON antes de meterla en el documento.
///
/// **Todo** texto del acta es texto que escribió quien la entrega. Este documento
/// es el que se anexa a un dictamen, así que una cadena con saltos de línea y
/// almohadillas puede fabricar SECCIONES ENTERAS —un «## 6. Fecha cierta» falso,
/// una cita «> VERIFICADO» falsa— indistinguibles de las que genera la
/// herramienta, porque serían byte a byte iguales. La versión anterior solo
/// cambiaba `|` y `\n`, y solo se aplicaba a 6 de los casi 40 campos que se
/// interpolan: lo cazó la tercera revisión de seguridad.
///
/// Se neutraliza, en este orden:
///   - los tres terminadores de línea (`\r\n`, `\n`, `\r`) y el tabulador, que
///     CommonMark también trata como fin de línea o sangría;
///   - el resto de caracteres de control, que no tienen nada que hacer aquí;
///   - las tuberías, que romperían las tablas;
///   - los acentos graves, que abrirían o cerrarían bloques de código;
///   - y el marcador de estructura al PRINCIPIO de la cadena (`#`, `>`, `-`,
///     `*`, `+`), que es lo que convierte un texto en un encabezado o una cita.
fn escapar(s: &str) -> String {
    let mut limpio = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\r' | '\n' | '\t' => limpio.push(' '),
            '|' => limpio.push_str("\\|"),
            '`' => limpio.push_str("\\`"),
            c if c.is_control() => limpio.push(' '),
            c => limpio.push(c),
        }
    }
    // Un `#` a mitad de frase es inofensivo; al principio de línea es un
    // encabezado. Como aquí ya no quedan saltos de línea, basta con el inicio.
    let recortado = limpio.trim_start();
    let prefijo_peligroso = recortado
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '#' | '>' | '-' | '*' | '+'));
    if prefijo_peligroso {
        format!("\\{recortado}")
    } else {
        limpio
    }
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

/// Lo que el VERIFICADOR concluyó sobre el sello de tiempo, que es lo único que
/// este documento puede afirmar.
///
/// Existe porque el acta legible se generaba leyendo `acta.sello_tiempo` —campos
/// del JSON que entrega la parte interesada— sin comprobar nada: quien quisiera
/// escribía la fecha y la autoridad que le conviniera, firmaba el acta con su
/// propia clave, y el documento salía diciendo que una autoridad independiente
/// había certificado esa fecha. Y el propio aviso del documento afirmaba que la
/// herramienta había verificado la firma del token, en el único camino que no la
/// verificaba. Lo cazó la revisión de seguridad.
pub enum SelloVerificado {
    /// El acta no lleva sello de tiempo.
    Ausente,
    /// El token está correctamente firmado. `Confianza` dice si además la
    /// identidad de la autoridad quedó acreditada contra un ancla.
    Valido(crate::sello_tiempo::DatosSello, crate::firma_cms::Confianza),
    /// El sello no se sostiene: no corresponde a esta acta, o no está firmado.
    Invalido(String),
}

/// Lo que el verificador concluyó sobre el acta MISMA: su raíz de Merkle y su
/// firma triple.
///
/// Va aparte del sello porque son dos preguntas distintas y hasta la tercera
/// revisión el documento no respondía ni a la primera: `orden_acta` llamaba a
/// `verificar_sello()`, tiraba el resultado a `stderr` y generaba igual un
/// documento que afirmaba «cualquier cambio en un byte produce una raíz distinta»
/// y «cobertura: la totalidad del acta», leyendo la raíz y la firma del propio
/// JSON. Dos líneas en stderr no viajan al juzgado; el documento sí.
pub enum ActaVerificada {
    /// Raíz y firma comprueban contra la clave pública que el acta declara.
    Valida,
    /// No comprueban. El documento no puede afirmar integridad ni cobertura.
    Invalida(String),
}

impl ActaVerificada {
    fn es_valida(&self) -> bool {
        matches!(self, ActaVerificada::Valida)
    }
}

pub fn markdown(acta: &Acta, verificada: &ActaVerificada, sello: &SelloVerificado) -> String {
    let mut m = String::new();
    let leidos = acta.elementos.iter().filter(|e| e.estado == "leido").count();
    let errores: Vec<_> = acta.elementos.iter().filter(|e| e.estado.starts_with("ERROR")).collect();
    let bytes: u64 = acta.elementos.iter().map(|e| e.bytes).sum();

    m.push_str("# Acta de sellado de evidencia digital\n\n");
    m.push_str(&format!("**Referencia:** {}\n\n", escapar(&acta.caso.referencia)));
    m.push_str(&format!("{}\n\n", escapar(&acta.caso.descripcion)));

    m.push_str("## 1. Perito\n\n");
    m.push_str(&format!("- **Nombre:** {}\n", escapar(&acta.perito.nombre)));
    m.push_str(&format!("- **Identificación:** {}\n", escapar(&acta.perito.identificacion)));
    m.push_str(&format!(
        "- **Clave pública de verificación** — huella SHA-256:\n\n```\n{}\n```\n\n",
        huella(&acta.perito.clave_publica)
    ));

    m.push_str("## 2. Método de adquisición\n\n");
    m.push_str(&format!("- **Origen:** `{}`\n", escapar(&acta.adquisicion.origen)));
    m.push_str(&format!("- **Método:** {}\n", escapar(&acta.adquisicion.metodo)));
    m.push_str(&format!("- **Herramienta:** {}\n", escapar(&acta.adquisicion.herramienta)));
    m.push_str(&format!("- **Algoritmos:** {}\n", escapar(&acta.adquisicion.algoritmos)));
    m.push_str("- **Acceso:** exclusivamente de lectura. La herramienta no escribe dentro del origen.\n\n");

    m.push_str("### Registro horario\n\n");
    m.push_str(&format!("- **Inicio (UTC):** {}\n", escapar(&acta.adquisicion.reloj.inicio_utc)));
    m.push_str(&format!("- **Fin (UTC):** {}\n", escapar(&acta.adquisicion.reloj.fin_utc)));
    m.push_str(&format!("- **Desfase local respecto de UTC:** {}\n", escapar(&acta.adquisicion.reloj.desfase_local_utc)));
    m.push_str(&format!("- **Contraste del reloj:** {}\n\n", escapar(&acta.adquisicion.reloj.verificacion)));

    m.push_str("## 3. Resumen\n\n");
    m.push_str("| Elementos | Leídos | Ilegibles | Bytes |\n|---|---|---|---|\n");
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
    if let ActaVerificada::Invalida(motivo) = verificada {
        // No se imprime la raíz declarada acompañada de la frase que le da
        // sentido: sería exactamente la afirmación que acaba de fallar.
        m.push_str("**ESTA ACTA NO VERIFICA.** No se afirma integridad de nada.\n\n");
        m.push_str(&format!("Motivo: {}\n\n", escapar(motivo)));
        m.push_str("La raíz que el archivo declara está en el JSON, y NO corresponde a lo\n");
        m.push_str("que el archivo contiene, o su firma no es de quien dice ser. Este\n");
        m.push_str("documento no acredita nada; sirve para ver qué se pretendía acreditar.\n\n");
    } else {
        m.push_str("Raíz del árbol de Merkle construido sobre los elementos listados en el\n");
        m.push_str("anexo. Cualquier cambio en un byte, en una ruta o en el orden produce una\n");
        m.push_str("raíz distinta.\n\n");
        m.push_str(&format!("```\n{}\n```\n\n", escapar(&acta.raiz_merkle)));
    }

    m.push_str("## 5. Firma\n\n");
    match &acta.firma {
        Some(f) => {
            m.push_str(&format!("- **Algoritmo:** {}\n", escapar(&f.algoritmo)));
            if verificada.es_valida() {
                m.push_str("- **Cobertura:** la totalidad del acta en formato JSON, incluidos el\n");
                m.push_str("  listado de elementos y la raíz. **Comprobada.**\n\n");
            } else {
                m.push_str("- **Cobertura:** NINGUNA COMPROBADA. Esta firma **no verifica**\n");
                m.push_str("  contra la clave pública que el propio acta declara, así que no\n");
                m.push_str("  cubre el listado de elementos ni la raíz.\n\n");
            }
            m.push_str("Huella SHA-256 de la firma:\n\n");
            m.push_str(&format!("```\n{}\n```\n\n", huella(&f.valor)));
            m.push_str("> La firma y la clave completas están en el archivo JSON, no en este\n");
            m.push_str("> documento: impresas ocuparían cientos de páginas que nadie cotejaría.\n");
            m.push_str("> **La verificación se hace sobre el JSON**; este documento es para leer,\n");
            m.push_str("> no para verificar.\n\n");
        }
        None => m.push_str("**ACTA SIN FIRMAR.** No acredita nada mientras no se selle.\n\n"),
    }

    m.push_str("## 6. Fecha cierta\n\n");
    match sello {
        SelloVerificado::Invalido(motivo) => {
            // Nunca se calla: un acta con un sello que no se sostiene es
            // precisamente la que alguien querría presentar como fechada.
            m.push_str("**EL SELLO DE TIEMPO DE ESTA ACTA NO ES VÁLIDO.**\n\n");
            m.push_str(&format!("Motivo: {}\n\n", escapar(motivo)));
            m.push_str("Este documento NO acredita ninguna fecha. Si el acta llegó con un\n");
            m.push_str("sello, no es el que dice ser.\n\n");
        }
        SelloVerificado::Valido(t, confianza) => {
            // El sello acredita que EL VALOR DEL CAMPO `firma` ya existía en esa
            // fecha, no que el acta sea íntegra: son cosas distintas y el token no
            // cubre el cuerpo del acta. Si la firma del acta no verifica, hablar de
            // «la firma de esta acta» no significa nada, así que no se dice.
            if !verificada.es_valida() {
                m.push_str(
                    "El acta trae un sello de tiempo con firma válida, **pero la firma del \n\
                     acta no verifica** (numeral 5). El sello acredita que ese valor ya \n\
                     existía en la fecha indicada; NO acredita que este acta sea íntegra ni \n\
                     que su contenido estuviera cubierto por nada.\n\n",
                );
            } else if confianza.acredita_autoridad() {
                m.push_str(&format!(
                    "Una autoridad de sellado independiente certificó que la firma de esta \n\
                     acta ya existía el **{}**.\n\n",
                    escapar(&t.fecha_utc)
                ));
            } else {
                // Sin ancla no se escribe «certificó» ni «fecha cierta»: la firma
                // es válida, pero un autofirmado produce lo mismo.
                m.push_str(&format!(
                    "El sello de esta acta lleva una **firma válida** que dice que la firma \n\
                     del acta ya existía el **{}** — pero su autoridad **NO está \n\
                     acreditada**: el acta se verificó sin aportar la raíz de la autoridad \n\
                     (`--tsa-ca`), y sin eso un certificado autofirmado produciría este \n\
                     mismo resultado. Por eso este documento no afirma fecha cierta.\n\n",
                    escapar(&t.fecha_utc)
                ));
            }
            m.push_str(&format!(
                "- **Autoridad que firma:** {}\n",
                escapar(confianza.autoridad())
            ));
            m.push_str(&format!("- **Política de sellado:** {}\n", escapar(&t.politica)));
            m.push_str(&format!("- **Número de serie:** {}\n", escapar(&t.serie)));
            m.push_str("- **Protocolo:** RFC 3161, el mismo documento normativo con el que\n");
            m.push_str("  ONAC acredita el servicio de estampado cronológico en Colombia\n");
            m.push_str("  (criterio CEA-3.0-07; art. 161.5 del Decreto Ley 019 de 2012).\n\n");
            if let Some(st) = &acta.sello_tiempo {
                m.push_str("Huella SHA-256 del token:\n\n");
                m.push_str(&format!("```\n{}\n```\n\n", huella(&st.token)));
            }
            m.push_str("> **Alcance de esta comprobación.** Esta herramienta verificó que el\n");
            m.push_str("> sello corresponde exactamente a la firma de esta acta, y que el token\n");
            m.push_str("> está **correctamente firmado**: un único firmante, su certificado\n");
            m.push_str("> dentro del token, con el uso `id-kp-timeStamping`, los atributos que\n");
            m.push_str("> atan la firma a este mismo sello, y la firma válida con esa clave.\n");
            m.push_str(">\n");
            m.push_str("> **No hizo validación PKI completa**: sin revocación (CRL/OCSP), sin\n");
            m.push_str("> restricciones de nombre y sin políticas de certificación. Eso se hace\n");
            m.push_str("> con la herramienta estándar:\n");
            m.push_str(">\n");
            m.push_str("> ```bash\n");
            m.push_str("> openssl ts -verify -in sello.tsr -token_in -data firma.bin \\\n");
            m.push_str(">     -CAfile cadena_de_la_autoridad.pem\n");
            m.push_str("> ```\n");
            m.push_str(">\n");
            m.push_str("> El token completo está en el JSON para que cualquiera pueda hacerlo.\n\n");
        }
        SelloVerificado::Ausente => {
            m.push_str("**Esta acta NO lleva sello de tiempo de un tercero.**\n\n");
            m.push_str("En consecuencia acredita **orden relativo**, no fecha cierta oponible:\n");
            m.push_str("la hora que consta es la del reloj de la máquina del perito. Para fecha\n");
            m.push_str("oponible hace falta el sello de una autoridad de estampado cronológico.\n\n");
        }
    }

    m.push_str("## 7. Cómo verificar esta acta\n\n");
    m.push_str("Cualquier tercero puede comprobarla sin intervención del perito y sin\n");
    m.push_str("software propietario: el verificador es libre y su código es público.\n\n");
    m.push_str("```bash\ntunjo verificar acta.json                 # firma y coherencia interna\ntunjo verificar acta.json --origen RUTA   # además, contra el material en disco\n```\n\n");

    m.push_str("## 8. Alcance y límites\n\n");
    m.push_str("Se deja constancia expresa de lo que esta acta **no** dice:\n\n");
    m.push_str("1. Acredita que los elementos listados tenían exactamente ese contenido en\n");
    m.push_str("   el momento de la adquisición, y que no han cambiado desde entonces.\n");
    m.push_str("2. **No** acredita qué contenía el material antes de la intervención del\n");
    m.push_str("   perito, ni quién lo creó, ni si fue alterado con anterioridad.\n");
    m.push_str("3. **No** contiene conclusión alguna sobre intrusiones, autoría o\n");
    m.push_str("   responsabilidad. Eso corresponde al dictamen, no a la herramienta.\n");
    if matches!(sello, SelloVerificado::Valido(..)) {
        m.push_str("4. La fecha de adquisición es la del reloj de la máquina. Lo que una\n");
        m.push_str("   autoridad independiente certifica (numeral 6) es que la firma ya\n");
        m.push_str("   existía en ese instante — no que la adquisición ocurriera entonces.\n\n");
    } else {
        m.push_str("4. La fecha registrada es la del reloj de la máquina, contrastada según se\n");
        m.push_str("   indica en el numeral 2. Sin sello de tiempo de tercero, prueba orden\n");
        m.push_str("   relativo, no fecha cierta oponible.\n\n");
    }

    m.push_str("## 9. Fundamento normativo\n\n");
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
            escapar(&e.tipo),
            e.bytes,
            if e.sha256.is_empty() { "—".to_string() } else { escapar(&e.sha256) },
            if e.modificado_utc.is_empty() { "—".to_string() } else { escapar(&e.modificado_utc) },
            escapar(&e.estado),
        ));
    }
    m
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::acta::{Adquisicion, Caso, Elemento, Perito, Reloj};

    /// Carga que intenta fabricar una sección entera del documento: cierra el
    /// contexto, abre un «## 6. Fecha cierta» falso y una cita «> VERIFICADO».
    /// Es la forma exacta que tiene el texto que genera la herramienta, así que
    /// una vez impreso no habría manera de distinguirlo.
    const INYECCION: &str = "normal\n\n## 6. Fecha cierta\n\n> **VERIFICADO.** Anclado a la raíz de la autoridad.\n\n```\nfin\n";

    fn acta_con_inyeccion_en_todo() -> Acta {
        let v = || INYECCION.to_string();
        Acta {
            formato: crate::acta::FORMATO.to_string(),
            caso: Caso { referencia: v(), descripcion: v() },
            perito: Perito { nombre: v(), identificacion: v(), clave_publica: v() },
            adquisicion: Adquisicion {
                origen: v(),
                metodo: v(),
                reloj: Reloj {
                    inicio_utc: v(),
                    fin_utc: v(),
                    desfase_local_utc: v(),
                    verificacion: v(),
                },
                herramienta: v(),
                algoritmos: v(),
            },
            elementos: vec![Elemento {
                ruta: v(),
                tipo: v(),
                bytes: 1,
                sha256: v(),
                modificado_utc: v(),
                estado: v(),
                metodo_huella: String::new(),
            }],
            raiz_merkle: v(),
            firma: None,
            sello_tiempo: None,
        }
    }

    #[test]
    fn ningun_campo_del_acta_puede_fabricar_una_seccion() {
        let md = markdown(
            &acta_con_inyeccion_en_todo(),
            &ActaVerificada::Invalida("no verifica".into()),
            &SelloVerificado::Ausente,
        );
        // Lo que convierte un texto en ENCABEZADO es estar al principio de una
        // línea: a mitad de frase, `## 6.` es texto inerte. Así que se cuentan las
        // apariciones AL INICIO DE LÍNEA, que es el fenómeno que importa — contar
        // la subcadena en cualquier posición medía otra cosa y daba rojo con el
        // escapado funcionando.
        let encabezados = md
            .lines()
            .filter(|l| l.trim_start().starts_with("## 6. Fecha cierta"))
            .count();
        assert_eq!(encabezados, 1, "un campo del acta fabricó una sección:\n{md}");

        // Lo mismo para la cita que finge un veredicto: `>` solo cita al principio.
        let citas_falsas = md
            .lines()
            .filter(|l| l.trim_start().starts_with("> **VERIFICADO."))
            .count();
        assert_eq!(citas_falsas, 0, "una cita falsa de veredicto llegó al documento:\n{md}");

        // Y ninguna línea del documento puede haber nacido de un salto de línea
        // inyectado: el escapador los aplana todos.
        assert!(
            !md.contains("\n\n## 6. Fecha cierta\n\n> **VERIFICADO."),
            "la carga reprodujo la plantilla entera:\n{md}"
        );
    }

    #[test]
    fn el_escapador_neutraliza_los_tres_terminadores_y_la_estructura() {
        // \r solo también es fin de línea en CommonMark; la versión anterior del
        // escapador solo trataba \n.
        assert!(!escapar("a\rb").contains('\r'));
        assert!(!escapar("a\r\nb").contains('\n'));
        assert!(!escapar("a\tb").contains('\t'));
        assert_eq!(escapar("a|b"), "a\\|b");
        assert_eq!(escapar("a`b`c"), "a\\`b\\`c");
        // Un marcador de estructura al principio se desactiva; a mitad de frase no
        // hace nada y no se toca.
        assert!(escapar("# título").starts_with('\\'));
        assert!(escapar("> cita").starts_with('\\'));
        assert!(escapar("- lista").starts_with('\\'));
        assert_eq!(escapar("nota # a mitad"), "nota # a mitad");
    }

    #[test]
    fn un_acta_que_no_verifica_no_afirma_integridad_ni_cobertura() {
        let mut a = acta_con_inyeccion_en_todo();
        a.caso = Caso { referencia: "R-1".into(), descripcion: "prueba".into() };
        let md = markdown(
            &a,
            &ActaVerificada::Invalida("la firma NO verifica".into()),
            &SelloVerificado::Ausente,
        );
        assert!(md.contains("ESTA ACTA NO VERIFICA"), "{md}");
        // La frase que da sentido a la raíz no puede aparecer si no verifica.
        assert!(
            !md.contains("produce una\nraíz distinta"),
            "afirma integridad de un acta que no verifica:\n{md}"
        );
    }
}

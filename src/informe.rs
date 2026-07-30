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

/// Neutraliza una cadena del JSON para meterla en el documento, EN LÍNEA.
///
/// # Seis rondas de revisión sobre esta función, y por qué esta es distinta
///
/// Todo texto del acta lo escribió quien la entrega, y este documento se anexa a un
/// dictamen: una cadena puede fabricar secciones enteras indistinguibles de las que
/// genera la herramienta. Las versiones anteriores fueron **listas negras de los
/// marcadores que se nos iban ocurriendo**, y cada ronda encontró el que faltaba:
/// primero el salto de línea, luego el HTML en crudo (que no necesita saltos),
/// luego la barra invertida que no se escapaba a sí misma, y en la sexta los
/// dígitos y la sintaxis EN LÍNEA —`[enlace]()`, `![imagen]()`— que mete píxeles
/// del atacante dentro del acta.
///
/// El cambio de enfoque: **se escapa toda la puntuación ASCII**, no una lista de
/// sospechosos. Es lo correcto porque CommonMark define exactamente eso —«cualquier
/// carácter de puntuación ASCII puede escaparse con barra invertida»— y **consume**
/// esa barra al renderizar. Así el documento renderizado muestra el texto TAL CUAL
/// era, y no hay marcador que se nos pueda olvidar: no hay estructura en Markdown
/// que no empiece por puntuación ASCII.
///
/// # La barra invertida nunca va ante algo que no sea puntuación
///
/// Es el otro hallazgo de la sexta ronda, y era **corrupción de la prueba sin
/// atacante**: CommonMark solo consume la barra ante puntuación, así que la regla
/// anterior convertía `1.png` en `\1.png` y una cédula `1.020.304.050` en
/// `\1.020.304.050` — visibles en el documento, y distintos del JSON que se firmó.
/// Una lista ordenada se desactiva escapando el PUNTO (`1\.`), no el dígito.
fn escapar(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 4);
    for c in s.chars() {
        match c {
            // Sin saltos de línea no hay bloque nuevo, y sin controles no se
            // reescribe una terminal si este texto acaba en una.
            '\r' | '\n' | '\t' => out.push(' '),
            c if c.is_control() => out.push(' '),
            // Entidades para los dos que abren HTML. Podrían ir con barra, pero la
            // entidad es inequívoca en cualquier renderizador, y el HTML fue la vía
            // que dos rondas no vieron.
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            // Toda la demás puntuación ASCII, escapada. La barra la consume el
            // renderizador, así que el resultado se LEE igual que el original.
            c if c.is_ascii_punctuation() => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// Igual, pero para el único campo que se interpola al PRINCIPIO de una línea.
///
/// `caso.descripcion` va a columna cero tras una línea en blanco, y ahí cuatro
/// espacios abren un bloque de código indentado — que no forja una sección, pero
/// deja el párrafo del acta en monoespaciado sin que nadie lo haya pedido. La
/// puntuación ya la neutraliza [`escapar`]; lo único que añade esto es quitar la
/// sangría inicial.
fn escapar_bloque(s: &str) -> String {
    escapar(s.trim_start())
}

/// ¿Son 64 dígitos hexadecimales, es decir, la forma de un SHA-256?
///
/// Se usa antes de imprimir un valor DENTRO de una valla de código, donde el
/// escapado no vale nada. Un valor que no pasa esto no se mete en la valla: se dice
/// que no tiene la forma esperada y se imprime escapado como texto.
fn es_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Texto plano para la SALIDA POR PANTALLA, no para el documento.
///
/// El acta legible se escapaba y la salida del programa no, y ahí vive el
/// veredicto que lee una persona: un `\u001b[2K` dentro de un campo del JSON borra
/// la línea que acaba de imprimirse y pinta encima «SELLO VÁLIDO». El código de
/// salida seguía siendo 1, pero nadie frente a un prompt lo mira. Cuarta revisión.
pub fn plano(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
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
    // Igual que en `resumen_elementos`: la verificabilidad la da la huella.
    let leidos = acta
        .elementos
        .iter()
        .filter(|e| e.estado == "leido" && !e.sha256.is_empty())
        .count();
    let errores: Vec<_> = acta.elementos.iter().filter(|e| e.estado.starts_with("ERROR")).collect();
    let bytes: u64 = acta.elementos.iter().map(|e| e.bytes).sum();

    m.push_str("# Acta de sellado de evidencia digital\n\n");
    m.push_str(&format!("**Referencia:** {}\n\n", escapar(&acta.caso.referencia)));
    m.push_str(&format!("{}\n\n", escapar_bloque(&acta.caso.descripcion)));

    m.push_str("## 1. Perito\n\n");
    m.push_str(&format!("- **Nombre:** {}\n", escapar(&acta.perito.nombre)));
    m.push_str(&format!("- **Identificación:** {}\n", escapar(&acta.perito.identificacion)));
    m.push_str(&format!(
        "- **Clave pública de verificación** — huella SHA-256:\n\n```\n{}\n```\n\n",
        huella(&acta.perito.clave_publica)
    ));

    m.push_str("## 2. Método de adquisición\n\n");
    m.push_str(&format!("- **Origen:** {}\n", escapar(&acta.adquisicion.origen)));
    m.push_str(&format!("- **Método:** {}\n", escapar(&acta.adquisicion.metodo)));
    m.push_str(&format!("- **Herramienta:** {}\n", escapar(&acta.adquisicion.herramienta)));
    m.push_str(&format!("- **Algoritmos:** {}\n", escapar(&acta.adquisicion.algoritmos)));
    // Esto es una propiedad de TUNJO cuando ÉL hizo la adquisición, no un hecho
    // que este documento pueda afirmar de un acta que se limita a leer: si la
    // escribió otro, «la herramienta» es la que diga el campo de arriba. Se
    // atribuye en vez de afirmarse. Misma clase que el «no han cambiado desde
    // entonces» de la ronda anterior. Quinta revisión.
    m.push_str(
        "- **Acceso declarado:** de solo lectura. Tunjo no escribe dentro del origen \n\
         cuando es él quien adquiere; para un acta emitida por otra herramienta, esto \n\
         es lo que declara el perito, no algo que este documento haya comprobado.\n\n",
    );

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
        m.push_str("> cubiertos por ninguna afirmación de integridad.\n");
        // Antes decía «de ellos solo se acredita que existían y que la lectura
        // falló», y era falso por dos motivos que encontró la sexta revisión. Uno:
        // no estaba gateado por el veredicto, así que un acta que no verifica
        // afirmaba haber acreditado algo. Dos: `ERROR:` incluye «no such file or
        // directory», así que ni en el caso válido se acredita la EXISTENCIA — lo
        // único que consta es que el perito registró esa ruta y que la lectura
        // falló. Afirmar la existencia de lo que el propio registro dice que no
        // estaba es la clase de frase que se cae en un contrainterrogatorio.
        if verificada.es_valida() {
            m.push_str("> Consta que el perito registró esa ruta y que la lectura falló; NO se\n");
            m.push_str("> acredita que el elemento existiera ni cuál era su contenido.\n\n");
        } else {
            m.push_str("> Y como la firma de esta acta no verifica (numeral 5), tampoco consta\n");
            m.push_str("> que el registro de estas rutas sea el que el perito hizo.\n\n");
        }
        for e in &errores {
            // Sin tramo de código: dentro de uno el escapado no vale nada (ni
            // barras ni entidades) y un acento grave en la ruta cierra el tramo
            // antes de tiempo. Se quitó en los demás sitios y este se escapó —
            // precisamente el que ninguna prueba renderizaba. Quinta revisión.
            m.push_str(&format!("> - {} — {}\n", escapar(&e.ruta), escapar(&e.estado)));
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
        // Dentro de una valla de código la barra invertida NO se consume, así que
        // aquí escapar mostraría las barras. Y no hace falta: en este camino la
        // raíz ya está comprobada contra `raiz_calculada()`, así que son 64 hex.
        // Si aun así no lo fueran, se dice y se saca de la valla en vez de
        // imprimir dentro de ella algo que no se pudo comprobar.
        if es_hex64(&acta.raiz_merkle) {
            m.push_str(&format!("```\n{}\n```\n\n", acta.raiz_merkle));
        } else {
            m.push_str(&format!(
                "**La raíz declarada no tiene la forma de un SHA-256:** {}\n\n",
                escapar(&acta.raiz_merkle)
            ));
        }
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
                     acta no verifica** (numeral 5). Lo único que el sello dice es que el \n\
                     valor guardado en el campo de firma ya existía en la fecha indicada; NO \n\
                     dice que este acta sea íntegra, ni que su contenido estuviera cubierto \n\
                     por nada, ni —si no se aportó `--tsa-ca`— de quién viene esa fecha.\n\n",
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
            m.push_str("> restricciones de nombre y sin políticas de certificación.\n");
            if !confianza.acredita_autoridad() {
                m.push_str("> **Y no comprobó a QUIÉN pertenece ese certificado**, porque no se\n");
                m.push_str("> aportó `--tsa-ca`: la identidad de la autoridad no está acreditada.\n");
            }
            m.push_str("> Eso se hace con la herramienta estándar:\n");
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
    if verificada.es_valida() {
        // Lo que el acta acredita es el CONTENIDO EN EL MOMENTO de la adquisición.
        // Que «no han cambiado desde entonces» es una afirmación sobre el disco de
        // hoy, y `tunjo acta` no lee ningún disco: eso solo lo puede decir
        // `tunjo verificar --origen`. Estaba escrito sin respaldo en TODOS los
        // caminos, válidos incluidos. Cuarta revisión de seguridad.
        m.push_str("1. Acredita que los elementos listados tenían exactamente ese contenido en\n");
        m.push_str("   el momento de la adquisición. Para contrastar contra el material de hoy,\n");
        m.push_str("   `tunjo verificar --origen RUTA`, que es otra comprobación y la dice aparte.\n");
    } else {
        m.push_str("1. **NO acredita nada del contenido de los elementos listados**: la firma de\n");
        m.push_str("   esta acta no verifica (numeral 5), así que el anexo es una lista sin\n");
        m.push_str("   respaldo criptográfico.\n");
    }
    m.push_str("2. **No** acredita qué contenía el material antes de la intervención del\n");
    m.push_str("   perito, ni quién lo creó, ni si fue alterado con anterioridad.\n");
    m.push_str("3. **No** contiene conclusión alguna sobre intrusiones, autoría o\n");
    m.push_str("   responsabilidad. Eso corresponde al dictamen, no a la herramienta.\n");
    // Un sello VÁLIDO pero SIN ANCLAR lo produce igual un certificado que el
    // adversario emitió hace un minuto, así que no puede sostener «una autoridad
    // independiente certifica». Se exige la autoridad acreditada. Cuarta revisión.
    if matches!(sello, SelloVerificado::Valido(_, c) if c.acredita_autoridad()) {
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
            "| {} | {} | {} | {} | {} | {} | {} |\n",
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
    const INYECCION: &str = concat!(
        "normal\n\n## 6. Fecha cierta\n\n> **VERIFICADO.** Anclado a la raíz.\n\n```\nfin\n",
        // HTML en crudo: CommonMark lo deja pasar y no necesita saltos de línea.
        // Era la vía que la lista negra de marcadores no cubría.
        "</p><h2>6. Fecha cierta</h2><blockquote><p><strong>VERIFICADO.</strong> ",
        "Anclado a la raíz de DigiCert.</p></blockquote><!--",
        // Un fence de virgulillas sin cerrar se comería el resto del documento;
        // los del template son de acentos graves y no lo cierran.
        "\n~~~\n",
        // Y un escape de terminal, que es lo que reescribe la salida por pantalla.
        "\u{1b}[2K\u{1b}MSELLO VÁLIDO"
    );

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

        // NINGÚN «<» de un campo puede llegar al documento: es lo que abre HTML,
        // y el HTML no necesita saltos de línea para fabricar un encabezado.
        assert!(
            !md.contains("<h2>") && !md.contains("<blockquote") && !md.contains("<!--"),
            "HTML en crudo llegó al documento:\n{md}"
        );
        // Ni un fence de virgulillas, que se comería el resto.
        assert!(
            !md.lines().any(|l| l.trim_start().starts_with("~~~")),
            "un fence inyectado abrió un bloque:\n{md}"
        );
        // Ni un carácter de control, que reescribiría la pantalla.
        assert!(
            !md.chars().any(|c| c.is_control() && c != '\n'),
            "un carácter de control sobrevivió al escapado"
        );
    }

    /// Deshace exactamente lo que deshace el renderizador: la barra invertida ante
    /// puntuación ASCII —que CommonMark consume— y las dos entidades.
    ///
    /// Existe para poder afirmar la propiedad que de verdad importa, en vez de
    /// enumerar qué caracteres se tocan y cuáles no. La versión anterior de esta
    /// prueba afirmaba que un `#` a mitad de frase se dejaba intacto: era cierto
    /// del diseño viejo —una lista negra de marcadores— y quedó obsoleta al cambiar
    /// a escapar toda la puntuación. Una prueba que fija el CÓMO envejece con cada
    /// rediseño; una que fija el QUÉ, no.
    fn desescapar(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut cs = s.chars().peekable();
        while let Some(c) = cs.next() {
            if c == '\\' && cs.peek().is_some_and(|s| s.is_ascii_punctuation()) {
                out.push(cs.next().expect("acabamos de mirarlo"));
                continue;
            }
            out.push(c);
        }
        out.replace("&lt;", "<").replace("&amp;", "&")
    }

    #[test]
    fn lo_escapado_se_renderiza_igual_que_el_original() {
        // LA propiedad: el documento anexado tiene que decir lo MISMO que el JSON
        // que se firmó. Es lo contrario del defecto que la sexta revisión encontró
        // —`1.png` impreso como `\1.png`—, y se comprueba sobre casos reales y
        // hostiles a la vez.
        for original in [
            "1.png",
            "1.020.304.050",
            "/casos/2026-0112/evidencia (copia).pdf",
            "informe_final-v2.tar.gz",
            "Perito: Juan Carlos Isaza Arenas",
            "a|b",
            "a`b`c",
            "# título",
            "![img](http://atacante/x.png)",
            "</p><h2>6. Fecha cierta</h2><!--",
            "&amp; ya escapado",
            "~~~",
            "cédula 1.020.304.050, folio 3º",
        ] {
            assert_eq!(
                desescapar(&escapar(original)),
                original,
                "el documento no dice lo mismo que el JSON para {original:?}"
            );
        }
    }

    #[test]
    fn el_escapador_neutraliza_los_terminadores_y_toda_la_puntuacion() {
        // Los tres terminadores y el tabulador: sin ellos no hay bloque nuevo.
        assert!(!escapar("a\rb").contains('\r'));
        assert!(!escapar("a\r\nb").contains('\n'));
        assert!(!escapar("a\tb").contains('\t'));
        assert!(!escapar("a\u{1b}[2Kb").chars().any(|c| c.is_control()));

        // Ninguna puntuación ASCII queda sin desactivar, y esa es la garantía que
        // sustituye a la lista de marcadores: no hay estructura en Markdown que no
        // empiece por puntuación.
        for c in (0x21u8..0x7f).map(char::from).filter(|c| c.is_ascii_punctuation()) {
            let salida = escapar(&format!("x{c}y"));
            let neutralizado = salida.contains(&format!("\\{c}"))
                || (c == '&' && salida.contains("&amp;"))
                || (c == '<' && salida.contains("&lt;"));
            assert!(neutralizado, "la puntuación {c:?} salió sin neutralizar: {salida}");
        }

        // Y el HTML no pasa ni al principio ni a mitad de línea.
        assert!(!escapar("<h2>x</h2>").contains('<'));
        assert!(!escapar("texto <h2>x").contains('<'));
    }

    #[test]
    fn la_variante_de_bloque_quita_la_sangria_que_abriria_codigo() {
        // Cuatro espacios a columna cero abren un bloque de código indentado. Solo
        // `caso.descripcion` se interpola ahí, y por eso solo esa variante lo trata.
        assert!(!escapar_bloque("    texto sangrado").starts_with(' '));
        assert_eq!(desescapar(&escapar_bloque("  hola")), "hola");
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

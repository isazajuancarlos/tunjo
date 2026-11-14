// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: AGPL-3.0-or-later
//! El acta: qué se recogió, cómo, cuándo y quién responde por ello.
//!
//! El acta **no concluye nada**. Dice qué bytes había, con qué método se
//! leyeron y quién firma esa afirmación. Todo lo que sea interpretación —si
//! hubo intrusión, si alguien borró algo— es del dictamen del perito, no de
//! una herramienta. Una herramienta que concluye es una herramienta que se
//! derrumba en el contrainterrogatorio.

use serde::{Deserialize, Serialize};

use crate::merkle;

/// Identificador del formato que se EMITE hoy. Va DENTRO de lo firmado: la
/// versión es parte de la identidad criptográfica del acta, así que no se puede
/// degradar ni promover sin romper la firma —cambiar de versión no puede pasar
/// por reinterpretar un acta vieja con reglas nuevas—.
///
/// **Por qué hay negociación de versión (v1/v2).** Los campos añadidos al acta
/// —las marcas MAC de [`Elemento`] (`accedido_utc`, `creado_utc`) y la procedencia
/// de [`Adquisicion`] (`fundamento`, `titulo_referencia`)— van omitidos del JSON
/// cuando están vacíos (`skip_serializing_if`), así que un binario NUEVO verifica
/// un acta vieja byte a byte idéntica: esa dirección la cubre el vector de firma.
/// La dirección peligrosa es la otra, la que motivó esto: un acta NUEVA leída por
/// un binario VIEJO. `serde` descarta en silencio los campos que el binario viejo
/// no declara (no hay `deny_unknown_fields`), éste recalcula la raíz de Merkle y
/// la firma SIN ellos, y un acta legítima cae en [`ErrorActa::RaizNoCoincide`] o
/// [`ErrorActa::FirmaInvalida`] — se lee como FORJADA. Marcando el acta nueva con
/// una versión que el binario viejo no reconoce, su propio chequeo de formato la
/// rechaza ANTES de recalcular nada, con un error honesto de versión («actualiza
/// el verificador») en lugar de una acusación de fraude sobre un acta buena.
pub const FORMATO: &str = "tunjo/acta-v2";

/// Prefijo de la familia de formatos de acta de tunjo. Un `formato` que empieza
/// así pero que no está en [`FORMATOS_ACEPTADOS`] es una VERSIÓN que este binario
/// no conoce (casi siempre más nueva), no basura de otro productor: por eso se
/// reporta como [`ErrorActa::VersionNoSoportada`] y nunca como `FormatoDesconocido`
/// ni, mucho menos, como `RaizNoCoincide`.
pub const FAMILIA_FORMATO: &str = "tunjo/acta-v";

/// La versión anterior, que se sigue ACEPTANDO al verificar: las actas emitidas
/// antes de los campos MAC/procedencia la declaran, y un peritaje ya entregado a
/// un juzgado no se reemite. **No se retira jamás** mientras exista en el mundo un
/// acta v1 que alguien pueda necesitar verificar.
pub const FORMATO_V1: &str = "tunjo/acta-v1";

/// Los formatos que este binario sabe verificar. Se EMITE [`FORMATO`]; se ACEPTA
/// cualquiera de éstos. La verificación es la MISMA para todos —`skip_serializing_if`
/// hace que `bytes_canonicos` reproduzca exactamente lo que cada emisor firmó, sea
/// cual sea la versión—, así que esta lista no duplica lógica de verificación: solo
/// enumera qué versiones NO son «forjadas». Un acta cuya versión no esté aquí se
/// rechaza por versión, sin llegar a recalcular la raíz.
pub const FORMATOS_ACEPTADOS: &[&str] = &[FORMATO_V1, FORMATO];

/// Algoritmos con los que se sella. Se escribe en el acta porque dentro de diez
/// años habrá que saber contra qué se verifica, y porque el CGP (art. 226.10)
/// exige declarar el método empleado.
pub const ALGORITMOS: &str =
    "SHA-256 (contenido y Merkle); firma 3-de-3: Ed25519 + ML-DSA-87 (FIPS 204) + SLH-DSA-SHA2-256s (FIPS 205)";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Caso {
    /// Radicado, número interno o referencia con la que el acta se cita.
    pub referencia: String,
    /// Qué se está sellando y en el marco de qué actuación.
    pub descripcion: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Perito {
    pub nombre: String,
    /// Documento de identidad o tarjeta profesional. Lo pide el CGP art. 226.
    pub identificacion: String,
    /// Clave pública triple-híbrida en base64. Es lo que permite a un tercero
    /// verificar sin pedirle nada al perito.
    pub clave_publica: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Reloj {
    /// Instante en que arrancó la adquisición, en UTC.
    pub inicio_utc: String,
    /// Instante en que terminó, en UTC.
    pub fin_utc: String,
    /// Desfase de la máquina respecto de UTC en el momento de sellar.
    pub desfase_local_utc: String,
    /// Cómo se contrastó el reloj con una fuente externa. Si el perito no lo
    /// declara, aquí queda escrito que NO se verificó — no se calla ni se
    /// rellena con un supuesto.
    pub verificacion: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Adquisicion {
    /// Ruta absoluta de la que se leyó, tal como la vio el perito.
    pub origen: String,
    /// Descripción del método: copia lógica en solo lectura, imagen previa,
    /// bloqueador de escritura empleado, etc.
    pub metodo: String,
    pub reloj: Reloj,
    pub herramienta: String,
    pub algoritmos: String,
    /// Fundamento LEGAL de la adquisición: bajo qué figura o autorización llegó
    /// el material a manos del perito — entrega voluntaria del titular,
    /// inspección extraprocesal (CGP art. 189), exhibición (art. 186), orden
    /// judicial con su radicado…
    ///
    /// NO concluye que la adquisición fue lícita —eso lo defiende el perito en el
    /// dictamen—; deja escrito bajo qué TÍTULO dice haberla hecho, que es lo que
    /// el art. 164 del CGP (la prueba obtenida con violación del debido proceso es
    /// nula de pleno derecho) obliga a poder defender. El `metodo` dice *cómo* se
    /// adquirió; el `fundamento`, *con qué derecho*.
    ///
    /// Opcional y **omitido del JSON cuando está vacío**, por el mismo mecanismo
    /// que `Elemento::metodo_huella`: así las actas firmadas antes de existir este
    /// campo conservan sus bytes canónicos y **verifican idénticas** (el vector de
    /// firma lo comprueba).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fundamento: String,
    /// Referencia IDENTIFICADORA del título de la adquisición: el radicado del
    /// auto que la ordenó, el número de la diligencia de exhibición (CGP art. 186)
    /// o de inspección extraprocesal (art. 189), el oficio de la prueba por
    /// informe (art. 275). El `fundamento` nombra la VÍA; este campo la ANCLA a
    /// su identificador — lo que el art. 164 obliga a poder defender, que el
    /// MARCO §2.4 resume como «orden judicial CON SU RADICADO». NO concluye
    /// licitud: deja escrito cuál es el instrumento.
    ///
    /// Distinto de `fundamento`, su ausencia NO es una omisión que haya que
    /// denunciar: hay vías legítimas sin radicado (la entrega voluntaria del
    /// titular no lo tiene), así que vacío se muestra «—» y no «NO DECLARADO».
    /// Omitido del JSON cuando está vacío, por el mismo mecanismo que
    /// `fundamento`: las actas firmadas antes de existir este campo conservan sus
    /// bytes canónicos y verifican idénticas (lo comprueba el vector de firma).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub titulo_referencia: String,
}

/// Un elemento recogido. `estado` distingue lo leído de lo que falló: un
/// archivo ilegible se registra como tal y nunca desaparece del acta en
/// silencio.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Elemento {
    /// Ruta relativa al origen. Relativa, para que el acta se verifique aunque
    /// la copia se monte en otro punto del sistema de archivos.
    pub ruta: String,
    pub tipo: String,
    pub bytes: u64,
    /// SHA-256 en hexadecimal del contenido. Vacío si no hay contenido que
    /// hashear (directorio) o si no se pudo leer.
    pub sha256: String,
    /// Última modificación en UTC según el sistema de archivos, o vacío si el
    /// sistema no la expone. NO se sustituye por la hora actual.
    pub modificado_utc: String,
    /// Último ACCESO (atime) en UTC según el sistema de archivos, o vacío si no
    /// lo expone (o si el montaje usa `noatime`). NO se sustituye por la hora
    /// actual. Para un ARCHIVO se toma ANTES de leer su contenido, así que es un
    /// acceso anterior al sellado. Para un DIRECTORIO queda VACÍO a propósito: el
    /// recorrido (`readdir`) lo abre, y su atime reflejaría el propio sellado —un
    /// dato que la herramienta causó (D20), no evidencia—. Aun en archivos, sobre
    /// material VIVO (no una copia en solo lectura ni un bloqueador de escritura)
    /// el atime puede ser el de una lectura previa del operador: por eso la
    /// adquisición se hace sobre copia o con bloqueador (guía de operador), y en
    /// una COPIA el atime/btime son los de la copia, no los del original.
    /// Omitido del JSON cuando está vacío, para que las actas firmadas antes de
    /// existir este campo conserven sus bytes canónicos.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub accedido_utc: String,
    /// CREACIÓN (btime) en UTC según el sistema de archivos, o vacío si el FS o el
    /// kernel no la exponen (muchos sistemas no la dan). NO se sustituye por la
    /// hora actual. Omitido del JSON cuando está vacío, igual que `accedido_utc`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub creado_utc: String,
    /// `leido`, `directorio`, `enlace -> destino` o `ERROR: <motivo>`.
    pub estado: String,
    /// CÓMO se calculó `sha256`. Vacío o ausente significa el método normal:
    /// SHA-256 de los bytes del archivo.
    ///
    /// Existe porque no todo lo que se sella se verifica leyendo bytes: algo
    /// puede sellarse por una huella que se recompute con OTRA herramienta. En
    /// ese caso el acta tiene que decir cuál, porque una huella que nadie sabe
    /// repetir no sirve como prueba — y `contrastar` no puede tratarla como un
    /// archivo normal, porque recomputaría el SHA-256 de los bytes y daría
    /// ALTERADO siempre. Ante un método que no conoce, el verificador dice NO
    /// VERIFICABLE nombrándolo, en vez de mentir dando por bueno —o por
    /// alterado— lo que no comprobó.
    ///
    /// Hoy solo se emite el método normal (vacío); el campo queda para que su
    /// ausencia signifique explícitamente «bytes del archivo», no una omisión.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub metodo_huella: String,
}

/// El método de huella que se verifica leyendo los bytes del archivo.
pub const HUELLA_ARCHIVO: &str = "";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Firma {
    pub algoritmo: String,
    /// Firma en base64 sobre los bytes canónicos del acta sin este campo.
    pub valor: String,
}

/// Sello de tiempo de un tercero sobre la firma del acta.
///
/// Va aparte de la firma porque se obtiene DESPUÉS de firmar: acredita que esa
/// firma —y con ella todo lo que cubre— ya existía en la fecha que certifica la
/// autoridad. Ver `crate::sello_tiempo`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SelloTiempo {
    /// Autoridad a la que se pidió, tal como la indicó el perito.
    pub autoridad: String,
    /// Instante certificado por la autoridad, en UTC.
    pub fecha_utc: String,
    /// Política de sellado bajo la que se emitió.
    pub politica: String,
    /// Número de serie del token para esa autoridad.
    pub serie: String,
    /// El token RFC 3161 completo, en base64 y sin tocar. Es lo que permite a
    /// un tercero validarlo con `openssl ts -verify` sin depender de nosotros.
    pub token: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Acta {
    pub formato: String,
    pub caso: Caso,
    pub perito: Perito,
    pub adquisicion: Adquisicion,
    pub elementos: Vec<Elemento>,
    /// Raíz del árbol de Merkle en hexadecimal.
    pub raiz_merkle: String,
    /// `None` mientras el acta no se ha firmado.
    pub firma: Option<Firma>,
    /// `None` si no se pidió sello de tiempo. Su ausencia NO es un defecto del
    /// acta: es un límite, y el informe lo declara como tal.
    #[serde(default)]
    pub sello_tiempo: Option<SelloTiempo>,
}

/// Errores del acta. Cada uno existe porque hay una forma concreta de que un
/// acta sea inválida y valga la pena distinguirla en el informe.
#[derive(Debug, PartialEq)]
pub enum ErrorActa {
    SinElementos,
    FormatoDesconocido(String),
    /// El acta declara un formato de la FAMILIA tunjo (`tunjo/acta-vN`) que este
    /// binario no sabe verificar —casi siempre uno más NUEVO que el binario—. Es
    /// distinto de `FormatoDesconocido` (otro productor, o basura) y, sobre todo,
    /// distinto de `RaizNoCoincide`: un verificador que se topa con una versión que
    /// no entiende debe pedir que lo actualicen, nunca acusar al acta de forjada.
    /// Ese error de atribución —un acta buena nueva leída como alterada por un
    /// verificador viejo— es justo lo que la negociación de versión existe para
    /// evitar (ver [`FORMATO`]).
    VersionNoSoportada {
        declarado: String,
        aceptados: String,
    },
    SinFirma,
    FirmaMalFormada,
    ClaveMalFormada,
    RaizNoCoincide { declarada: String, calculada: String },
    FirmaInvalida,
    SelloMalFormado,
    SelloNoCorresponde(String),
    /// Un elemento se declara «leido» y no trae huella. No está atado a nada, y sin
    /// esto el documento lo contaba como «con contenido verificable» y el numeral 1
    /// de «Alcance y límites» acreditaba su contenido. La recolección NUNCA emite
    /// ese estado —un archivo leído siempre lleva su SHA-256, incluso vacío—, así
    /// que existe solo en un acta fabricada. Lo cazó la sexta revisión.
    ElementoSinHuella {
        ruta: String,
    },
    /// El token sella lo que dice sellar, pero su firma CMS no se sostiene: sin
    /// firmante, con el certificado equivocado, o firmado por una clave que no es
    /// la del certificado que trae. Es distinto de `SelloNoCorresponde` —ahí el
    /// sello es de otra cosa— y por eso tiene su propio caso.
    SelloSinFirmaValida(String),
}

impl std::fmt::Display for ErrorActa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SinElementos => write!(f, "el acta no tiene elementos: no hay nada que sellar"),
            // `x` y `declarado` vienen del campo `formato` del JSON —texto que elige
            // quien entrega el acta—, así que se NEUTRALIZAN antes de salir, igual que
            // `ruta` en `ElementoSinHuella` (invariante 2): un escape de terminal en el
            // formato reescribiría el veredicto que lee una persona. `aceptados` es
            // nuestra constante y no haría falta, pero sanearlo tampoco cuesta.
            Self::FormatoDesconocido(x) => {
                write!(f, "formato de acta desconocido: {}", crate::texto::plano(x))
            }
            // NO se afirma nada sobre la autenticidad: un verificador que no conoce la
            // versión NO puede saber si el acta está alterada, así que no dice ni que lo
            // está ni que no (invariante 9: la herramienta no concluye más de lo que
            // prueba). La versión de un acta la fija tunjo al emitirla; una que este
            // binario no reconoce es, casi siempre, más reciente que él.
            Self::VersionNoSoportada { declarado, aceptados } => write!(
                f,
                "no se puede verificar: este binario no conoce el formato de acta «{}» (soporta {}). \
                 No se afirma ni que el acta es auténtica ni que está alterada: este verificador no \
                 sabe leer esta versión. Actualiza el verificador de tunjo a una versión que la soporte.",
                crate::texto::plano(declarado),
                crate::texto::plano(aceptados)
            ),
            Self::SinFirma => write!(f, "el acta no está firmada"),
            Self::FirmaMalFormada => write!(f, "la firma no es base64 válido o no mide lo esperado"),
            Self::ClaveMalFormada => write!(f, "la clave pública del acta no es válida"),
            Self::RaizNoCoincide { declarada, calculada } => write!(
                f,
                "la raíz de Merkle declarada ({declarada}) no corresponde a los elementos del acta ({calculada})"
            ),
            Self::FirmaInvalida => write!(f, "la firma NO verifica contra la clave pública del acta"),
            Self::SelloMalFormado => write!(f, "el sello de tiempo no es base64 válido"),
            Self::SelloNoCorresponde(m) => write!(f, "{m}"),
            Self::ElementoSinHuella { ruta } => write!(
                f,
                "el elemento «{}» se declara leído pero no trae huella: no está \
                 cubierto por nada y el acta no puede acreditar su contenido",
                crate::texto::plano(ruta)
            ),
            Self::SelloSinFirmaValida(m) => write!(
                f,
                "el sello de tiempo no está correctamente firmado, así que no acredita \
                 ninguna fecha: {m}"
            ),
        }
    }
}

impl std::error::Error for ErrorActa {}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Acta {
    /// Bytes que se firman: el acta completa **sin** la firma ni el sello.
    ///
    /// El sello queda fuera por necesidad, no por comodidad: se pide sobre el
    /// hash de la firma, así que no puede existir antes de firmar. Incluirlo
    /// haría el acta imposible de firmar y de verificar.
    ///
    /// Determinista porque `serde_json` respeta el orden de declaración de los
    /// campos de una `struct` y aquí no hay ningún mapa desordenado. Esa
    /// propiedad es la que permite verificar el acta dentro de diez años, así
    /// que está cubierta por una prueba.
    pub fn bytes_canonicos(&self) -> Vec<u8> {
        let mut desnuda = self.clone();
        desnuda.firma = None;
        desnuda.sello_tiempo = None;
        serde_json::to_vec(&desnuda).expect("el acta siempre serializa")
    }

    /// Comprueba el sello de tiempo, si lo hay.
    ///
    /// `Ok(None)` significa que el acta no lleva sello — que es un límite
    /// declarado, no un error. `Err` significa que lleva uno que no cuadra, y
    /// eso sí es grave: un sello que no corresponde a esta firma no acredita
    /// nada sobre esta acta.
    /// Verifica el sello de tiempo del acta: QUÉ sella y QUIÉN lo firmó.
    ///
    /// `anclas` son los certificados en los que el verificador ha decidido
    /// confiar. La firma CMS se comprueba SIEMPRE —un token sin firmante, o cuya
    /// firma no case con el certificado que trae, es un error, no una
    /// advertencia—; las anclas deciden si además se puede afirmar QUIÉN fechó.
    /// Con la lista vacía se devuelve [`Confianza::SinAnclar`] y quien lo reporte
    /// no puede llamar «fecha cierta» a esa fecha: un autofirmado llega hasta ahí.
    pub fn verificar_sello_tiempo(
        &self,
        anclas: &[x509_cert::Certificate],
    ) -> Result<Option<(crate::sello_tiempo::DatosSello, crate::firma_cms::Confianza)>, ErrorActa>
    {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let Some(sello) = &self.sello_tiempo else {
            return Ok(None);
        };
        let firma = self.firma.as_ref().ok_or(ErrorActa::SinFirma)?;
        let firma_bytes = STANDARD.decode(&firma.valor).map_err(|_| ErrorActa::FirmaMalFormada)?;
        let token = STANDARD.decode(&sello.token).map_err(|_| ErrorActa::SelloMalFormado)?;

        let hash = crate::sello_tiempo::hash_de(&firma_bytes);
        let datos = crate::sello_tiempo::verificar(&token, &hash)
            .map_err(|e| ErrorActa::SelloNoCorresponde(e.to_string()))?;
        let confianza = crate::firma_cms::verificar_firma(&token, &datos.fecha_utc, anclas)
            .map_err(|e| ErrorActa::SelloSinFirmaValida(e.to_string()))?;
        Ok(Some((datos, confianza)))
    }

    /// Raíz de Merkle calculada a partir de los elementos presentes.
    pub fn raiz_calculada(&self) -> Option<String> {
        let hojas: Vec<[u8; 32]> = self
            .elementos
            .iter()
            .map(|e| merkle::hoja(&serde_json::to_vec(e).expect("elemento serializable")))
            .collect();
        merkle::raiz(&hojas).map(|r| hex(&r))
    }

    /// Recalcula y fija la raíz. Se llama antes de firmar.
    pub fn fijar_raiz(&mut self) -> Result<(), ErrorActa> {
        self.raiz_merkle = self.raiz_calculada().ok_or(ErrorActa::SinElementos)?;
        Ok(())
    }

    /// Comprueba que este binario SABE leer la versión del acta, antes de intentar
    /// verificar o interpretar nada.
    ///
    /// Separado de [`Acta::verificar_sello`] a propósito: deja que el CLI rechace
    /// una versión que no entiende como lo que es —un límite del verificador, no un
    /// defecto del acta— y falle con el código de operación (2), sin llegar a emitir
    /// un veredicto de validez sobre un documento cuyo esquema no conoce. Verificar
    /// una versión futura leyéndola con reglas viejas es justo el error de atribución
    /// que la negociación de versión existe para evitar (ver [`FORMATO`]).
    ///
    /// Discrimina: una versión de la familia tunjo que no está en
    /// [`FORMATOS_ACEPTADOS`] es [`ErrorActa::VersionNoSoportada`] (actualiza el
    /// verificador); cualquier otra cosa es [`ErrorActa::FormatoDesconocido`] (otro
    /// productor, o basura).
    pub fn asegurar_version(&self) -> Result<(), ErrorActa> {
        if FORMATOS_ACEPTADOS.contains(&self.formato.as_str()) {
            return Ok(());
        }
        Err(if self.formato.starts_with(FAMILIA_FORMATO) {
            ErrorActa::VersionNoSoportada {
                declarado: self.formato.clone(),
                aceptados: FORMATOS_ACEPTADOS.join(", "),
            }
        } else {
            ErrorActa::FormatoDesconocido(self.formato.clone())
        })
    }

    /// Verificación **completa**: formato, raíz y firma.
    ///
    /// El orden importa. Verificar solo la firma dejaría pasar un acta cuya
    /// raíz no corresponde a sus elementos: la firma cubre el JSON entero,
    /// incluida una raíz mentirosa, y sin recalcularla el sello certificaría
    /// una lista que nadie comprobó.
    pub fn verificar_sello(&self) -> Result<(), ErrorActa> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use quipu::pqsign::TripleVerifyingKey;

        // Negociación de versión ANTES de tocar la raíz o la firma: una versión que
        // este binario no conoce se reporta como tal, nunca como «forjada». Ese orden
        // es la garantía —un acta nueva ante un verificador viejo no puede terminar
        // acusada de alterada (ver `FORMATO`)—.
        self.asegurar_version()?;
        // Antes que la raíz y que la firma: un acta que declara contenido sin
        // huella no acredita nada, y da igual que su firma cuadre. Fallar aquí es
        // lo que impide que el documento afirme sobre ella (directiva de fallar en
        // vez de suponer).
        if let Some(e) = self
            .elementos
            .iter()
            .find(|e| e.estado == "leido" && e.sha256.is_empty())
        {
            return Err(ErrorActa::ElementoSinHuella { ruta: e.ruta.clone() });
        }
        let calculada = self.raiz_calculada().ok_or(ErrorActa::SinElementos)?;
        if calculada != self.raiz_merkle {
            return Err(ErrorActa::RaizNoCoincide {
                declarada: self.raiz_merkle.clone(),
                calculada,
            });
        }
        let firma = self.firma.as_ref().ok_or(ErrorActa::SinFirma)?;
        let sig = STANDARD
            .decode(&firma.valor)
            .map_err(|_| ErrorActa::FirmaMalFormada)?;
        let vk_bytes = STANDARD
            .decode(&self.perito.clave_publica)
            .map_err(|_| ErrorActa::ClaveMalFormada)?;
        let vk = TripleVerifyingKey::from_bytes(&vk_bytes).ok_or(ErrorActa::ClaveMalFormada)?;

        if vk.verify(&self.bytes_canonicos(), &sig) {
            Ok(())
        } else {
            Err(ErrorActa::FirmaInvalida)
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// El `Display` de `ElementoSinHuella` sale a pantalla (main.rs) con la `ruta`,
    /// que es texto ajeno del acta: un RLO/ancho cero en ella debe neutralizarse por
    /// `texto::plano`, no por una copia local. Caso rojo del hunk que sin-caso-rojo
    /// marcó sin cubrir (concilio 2026-10-12).
    #[test]
    fn el_error_elemento_sin_huella_neutraliza_invisibles() {
        let e = ErrorActa::ElementoSinHuella { ruta: "a\u{202E}b\u{200B}c\u{E0041}".into() };
        let s = e.to_string();
        for peligroso in ['\u{202E}', '\u{200B}', '\u{E0041}'] {
            assert!(!s.contains(peligroso), "U+{:04X} llegó a la salida: {s:?}", peligroso as u32);
        }
    }

    pub fn acta_de_prueba() -> Acta {
        Acta {
            formato: FORMATO.to_string(),
            caso: Caso { referencia: "R-1".into(), descripcion: "prueba".into() },
            perito: Perito {
                nombre: "Perito".into(),
                identificacion: "CC 1".into(),
                clave_publica: String::new(),
            },
            adquisicion: Adquisicion {
                origen: "/tmp/x".into(),
                metodo: "copia lógica en solo lectura".into(),
                reloj: Reloj {
                    inicio_utc: "2026-07-26T10:00:00Z".into(),
                    fin_utc: "2026-07-26T10:00:01Z".into(),
                    desfase_local_utc: "-05:00".into(),
                    verificacion: "NO VERIFICADO".into(),
                },
                herramienta: "tunjo 0.1.0".into(),
                algoritmos: ALGORITMOS.into(),
                fundamento: String::new(),
                titulo_referencia: String::new(),
            },
            elementos: vec![Elemento {
                ruta: "a.txt".into(),
                tipo: "archivo".into(),
                bytes: 3,
                sha256: "aa".into(),
                modificado_utc: "2026-07-26T09:00:00Z".into(),
                accedido_utc: String::new(),
                creado_utc: String::new(),
                estado: "leido".into(),
                metodo_huella: String::new(),
            }],
            raiz_merkle: String::new(),
            firma: None,
            sello_tiempo: None,
        }
    }

    #[test]
    fn los_bytes_canonicos_no_dependen_de_la_firma() {
        let mut a = acta_de_prueba();
        let antes = a.bytes_canonicos();
        a.firma = Some(Firma { algoritmo: "x".into(), valor: "y".into() });
        assert_eq!(antes, a.bytes_canonicos(), "firmar no puede cambiar lo firmado");
    }

    #[test]
    fn los_bytes_canonicos_son_estables() {
        let a = acta_de_prueba();
        for _ in 0..50 {
            assert_eq!(a.bytes_canonicos(), acta_de_prueba().bytes_canonicos());
        }
    }

    #[test]
    fn cambiar_cualquier_campo_cambia_lo_firmado() {
        let base = acta_de_prueba().bytes_canonicos();
        let mut a = acta_de_prueba();
        a.elementos[0].sha256 = "bb".into();
        assert_ne!(base, a.bytes_canonicos());

        let mut b = acta_de_prueba();
        b.adquisicion.reloj.inicio_utc = "2026-07-26T10:00:02Z".into();
        assert_ne!(base, b.bytes_canonicos());

        let mut c = acta_de_prueba();
        c.caso.referencia = "R-2".into();
        assert_ne!(base, c.bytes_canonicos());

        // Los campos NUEVOS (#2 procedencia, #3 marcas MAC) tienen que quedar
        // DENTRO de lo firmado: un título de procedencia o una marca de tiempo
        // que no estuviera cubierta por la firma se podría alterar sin invalidar
        // el acta. Es la pareja del vector de firma: aquí se prueba que ENTRAN;
        // allí, que un acta vieja SIN ellos sigue verificando (skip_serializing).
        let mut d = acta_de_prueba();
        d.adquisicion.titulo_referencia = "Auto 2026-00123 del Juzgado 5 Civil".into();
        assert_ne!(base, d.bytes_canonicos(), "la referencia del título no entró en lo firmado");

        let mut e = acta_de_prueba();
        e.elementos[0].accedido_utc = "2026-07-26T08:00:00Z".into();
        assert_ne!(base, e.bytes_canonicos(), "el acceso (atime) no entró en lo firmado");

        let mut g = acta_de_prueba();
        g.elementos[0].creado_utc = "2026-07-20T00:00:00Z".into();
        assert_ne!(base, g.bytes_canonicos(), "la creación (btime) no entró en lo firmado");
    }

    #[test]
    fn acta_sin_elementos_no_tiene_raiz() {
        let mut a = acta_de_prueba();
        a.elementos.clear();
        assert_eq!(a.fijar_raiz(), Err(ErrorActa::SinElementos));
    }

    #[test]
    fn una_raiz_mentirosa_se_detecta_aunque_la_firma_sea_valida() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let (vk, sk) = quipu::pqsign::generate_triple_keypair();
        let mut a = acta_de_prueba();
        a.perito.clave_publica = STANDARD.encode(vk.to_bytes());
        // Raíz que NO corresponde a los elementos, y firma auténtica encima.
        a.raiz_merkle = "00".repeat(32);
        let sig = sk.sign(&a.bytes_canonicos());
        a.firma = Some(Firma { algoritmo: ALGORITMOS.into(), valor: STANDARD.encode(&sig) });

        match a.verificar_sello() {
            Err(ErrorActa::RaizNoCoincide { .. }) => {}
            otro => panic!("la firma válida tapó una raíz falsa: {otro:?}"),
        }
    }
}

/// **El vector fijo de FIRMA, y por qué las 115 pruebas de tunjo no bastaban.**
///
/// Todas las demás firman y verifican con el MISMO binario: miden el códec
/// contra sí mismo, y pasarían en verde aunque `SIGN_TRIPLE_CONTEXT` de quipu
/// —`b"quipu/v4/sign-triple"`— o la construcción de la preimagen cambiaran. El
/// vector de `clave.rs` ancla el CONTENEDOR de la clave y la derivación de las
/// tres semillas, que no es poco, pero **nunca firma ni verifica nada con ella**.
///
/// Lo que se rompía en silencio es lo único que este producto promete: **un acta
/// ya presentada en un juzgado no se regenera**. Una clave la vuelve a emitir el
/// perito; un peritaje entregado que deja de verificarse no tiene arreglo — y el
/// daño no se vería, porque las 115 pruebas seguirían verdes.
///
/// Lo señalaron por separado dos revisiones de seguridad del 2026-08-05
/// (guaca#17 obs.2 y tunjo#15 obs.O2), que es la señal de que no era manía de un
/// revisor. En guaca la mitad equivalente ya está cerrada
/// (`firma::una_firma_de_2026_sigue_verificando`).
#[cfg(test)]
mod vector_de_firma {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    /// El acta REAL sellada el 2026-08-12 con la clave del vector de `clave.rs`
    /// —la misma que lleva en el repositorio desde el 2026-08-05— y con la quipu
    /// que pide el `Cargo.toml`. **No se regenera**: ese es el punto.
    const ACTA_2026: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fijos/acta_2026.json"
    ));

    fn acta_del_vector() -> Acta {
        serde_json::from_str(ACTA_2026).expect("el acta fija del 2026-08-12 dejó de parsear")
    }

    /// El verde. Si se pone rojo al subir quipu, **NO se regenera el archivo**:
    /// significa que las actas emitidas hasta hoy dejaron de verificar, y eso se
    /// decide y se comunica.
    #[test]
    fn un_acta_de_2026_sigue_verificando() {
        assert_eq!(
            acta_del_vector().verificar_sello(),
            Ok(()),
            "un acta sellada el 2026-08-12 dejó de verificar: TODO peritaje ya \
             entregado pasa a no poder acreditarse, y eso no se arregla reemitiendo"
        );
    }

    /// PRIMER ROJO — se mide el CONTENIDO. Se altera un byte de lo sellado, no
    /// de la firma: es lo que pasa cuando alguien edita un elemento del acta
    /// después de firmarla. Sin esto, un `verificar_sello` que devolviera `Ok`
    /// siempre pasaría el verde de arriba.
    ///
    /// Falla por `RaizNoCoincide` y no por `FirmaInvalida`, y está bien que así
    /// sea: la raíz se recalcula ANTES que la firma justamente para que una
    /// lista manipulada no llegue a apoyarse en una firma que la cubre.
    #[test]
    fn alterar_el_contenido_del_acta_fija_la_invalida() {
        let mut a = acta_del_vector();
        a.elementos[0].sha256 = "00".repeat(32);
        assert!(
            matches!(a.verificar_sello(), Err(ErrorActa::RaizNoCoincide { .. })),
            "se alteró el contenido sellado y el acta siguió acreditándolo"
        );
    }

    /// SEGUNDO ROJO — se mide la FIRMA, que es cosa distinta del primero. Aquí
    /// el contenido queda intacto y la raíz cuadra: lo único que se mueve es la
    /// firma. Con solo el rojo de arriba, un verificador que ignorase la firma y
    /// se conformara con la raíz pasaría igual de verde.
    #[test]
    fn alterar_la_firma_del_acta_fija_la_invalida() {
        let mut a = acta_del_vector();
        let firma = a.firma.as_ref().expect("el vector va firmado");
        let mut bytes = STANDARD.decode(&firma.valor).expect("base64 de la firma");
        let n = bytes.len();
        bytes[n - 1] ^= 0x01;
        a.firma = Some(Firma {
            algoritmo: firma.algoritmo.clone(),
            valor: STANDARD.encode(&bytes),
        });
        assert_eq!(a.verificar_sello(), Err(ErrorActa::FirmaInvalida));
    }

    /// TERCER ROJO — la IDENTIDAD del firmante. El acta trae la clave pública
    /// dentro, así que cambiarla por otra tiene que invalidar: si no, cualquiera
    /// podría presentar un acta ajena como propia sustituyendo ese campo.
    #[test]
    fn cambiar_la_clave_publica_del_acta_fija_la_invalida() {
        let (vk, _) = quipu::pqsign::generate_triple_keypair();
        let mut a = acta_del_vector();
        a.perito.clave_publica = STANDARD.encode(vk.to_bytes());
        assert!(matches!(
            a.verificar_sello(),
            Err(ErrorActa::FirmaInvalida) | Err(ErrorActa::ClaveMalFormada)
        ));
    }

    /// **El acta la firmó el MISMO perito que el vector de `clave.rs`**, y esto
    /// lo comprueba en vez de dejarlo escrito en un comentario. Importa porque
    /// las dos anclas se apoyan la una en la otra: si alguien regenerase el
    /// `.clave` sin regenerar el acta, este banco quedaría midiendo dos cosas
    /// que ya no tienen nada que ver y nadie lo vería.
    ///
    /// La huella es la de `clave::pruebas::PUBLICA_2026`, que es privado: se
    /// compara por su valor, medido con quipu 0.10.0 el 2026-08-05.
    #[test]
    fn el_vector_usa_la_clave_del_otro_vector() {
        use sha2::{Digest, Sha256};
        let a = acta_del_vector();
        let bytes = STANDARD.decode(&a.perito.clave_publica).expect("base64");
        let huella: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            huella, "9c0f277bf06693dbe5d9a926bc14664d0e46c317ea99647ac4bb52bcc20cc451",
            "el acta fija NO la firmó el perito del vector de `clave.rs`: las dos anclas \
             dejaron de hablar del mismo firmante"
        );
    }

    /// Solo para GENERAR el vector. Ignorada: se corre a mano, y únicamente
    /// cuando la decisión de romper la compatibilidad ya está tomada.
    ///
    ///     cargo test --lib vector_de_firma::generar -- --ignored --nocapture
    #[test]
    #[ignore = "genera tests/fijos/acta_2026.json; no mide nada"]
    fn generar_el_acta_fija() {
        use crate::clave;

        // La MISMA clave del vector de `clave.rs`: así el ancla de la firma y la
        // del contenedor de la clave hablan del mismo perito, y una sola rotura
        // de quipu las pone rojas a las dos por su propia vía.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("de_2026.clave");
        std::fs::write(&ruta, STANDARD.decode(CLAVE_2026_B64).expect("base64")).unwrap();
        let sk = clave::cargar(&ruta, "contrasena-de-prueba-larga-2026").expect("abrir la clave");

        let mut a = Acta {
            formato: FORMATO.to_string(),
            caso: Caso {
                referencia: "VECTOR-2026".into(),
                descripcion: "acta fija del banco: no corresponde a ningún peritaje real".into(),
            },
            perito: Perito {
                nombre: "Perito del vector".into(),
                identificacion: "CC 00000000".into(),
                clave_publica: STANDARD.encode(sk.verifying_key().to_bytes()),
            },
            adquisicion: Adquisicion {
                origen: "/vector/2026".into(),
                metodo: "copia lógica en solo lectura".into(),
                reloj: Reloj {
                    inicio_utc: "2026-08-12T12:00:00Z".into(),
                    fin_utc: "2026-08-12T12:00:01Z".into(),
                    desfase_local_utc: "-05:00".into(),
                    verificacion: "NO VERIFICADO".into(),
                },
                herramienta: "tunjo (vector fijo)".into(),
                algoritmos: ALGORITMOS.into(),
                // VACÍO a propósito: omitido del JSON, el acta del vector conserva
                // sus bytes canónicos y su firma congelada sigue verificando.
                fundamento: String::new(),
                titulo_referencia: String::new(),
            },
            elementos: vec![
                Elemento {
                    ruta: "prueba.txt".into(),
                    tipo: "archivo".into(),
                    bytes: 12,
                    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                        .into(),
                    modificado_utc: "2026-08-12T11:00:00Z".into(),
                    accedido_utc: String::new(),
                    creado_utc: String::new(),
                    estado: "leido".into(),
                    metodo_huella: String::new(),
                },
                Elemento {
                    ruta: "carpeta".into(),
                    tipo: "directorio".into(),
                    bytes: 0,
                    sha256: String::new(),
                    modificado_utc: "2026-08-12T11:00:00Z".into(),
                    accedido_utc: String::new(),
                    creado_utc: String::new(),
                    estado: "directorio".into(),
                    metodo_huella: String::new(),
                },
            ],
            raiz_merkle: String::new(),
            firma: None,
            sello_tiempo: None,
        };
        a.fijar_raiz().expect("raíz");
        let sig = sk.sign(&a.bytes_canonicos());
        a.firma = Some(Firma { algoritmo: ALGORITMOS.into(), valor: STANDARD.encode(&sig) });
        assert_eq!(a.verificar_sello(), Ok(()), "el vector recién generado no verifica");

        let json = serde_json::to_string_pretty(&a).unwrap();
        let destino = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fijos/acta_2026.json");
        std::fs::write(&destino, json).unwrap();
        println!("escrito: {}", destino.display());
    }

    // ───────────────────────── NEGOCIACIÓN DE VERSIÓN v1/v2 ─────────────────────────
    //
    // El bloque de arriba ancla la v1 (el fijo `acta_2026.json`, SIN campos nuevos).
    // Lo que sigue ancla la v2 —la que se emite hoy, CON marcas MAC y procedencia— y
    // la garantía que cierra el residuo: una versión que el binario no conoce se
    // reporta como tal, nunca como «forjada».

    /// El fijo v2: un acta con los campos de la v2 LLENOS (marcas MAC + procedencia),
    /// firmada con la MISMA clave del vector. Ancla el camino de verificación de la
    /// versión que se emite hoy, igual que `ACTA_2026` ancla la v1. **No se regenera**:
    /// romperlo significa que un acta v2 ya emitida dejó de verificar.
    const ACTA_V2_2026: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fijos/acta_v2_2026.json"
    ));

    fn acta_v2_del_vector() -> Acta {
        serde_json::from_str(ACTA_V2_2026).expect("el acta fija v2 dejó de parsear")
    }

    /// El verde de la v2: un acta que SÍ trae los campos nuevos verifica por el camino
    /// actual. Es el par del verde de la v1 (`un_acta_de_2026_sigue_verificando`):
    /// juntos prueban que el binario de hoy acepta las DOS versiones.
    #[test]
    fn un_acta_v2_sigue_verificando() {
        assert_eq!(acta_v2_del_vector().verificar_sello(), Ok(()));
        assert_eq!(acta_v2_del_vector().formato, FORMATO, "el fijo v2 debe declarar la versión actual");
    }

    /// Mutante del contenido v2 por un campo EXCLUSIVO de la v2: alterar una marca
    /// MAC (que entra en la hoja de Merkle) pone roja la raíz. Sin esto, el verde de
    /// arriba pasaría aunque los campos nuevos no estuvieran cubiertos por la raíz.
    #[test]
    fn alterar_una_marca_mac_del_fijo_v2_la_invalida() {
        let mut a = acta_v2_del_vector();
        assert!(!a.elementos[0].accedido_utc.is_empty(), "el fijo v2 debe traer atime para que esto mida algo");
        a.elementos[0].accedido_utc = "2000-01-01T00:00:00Z".into();
        assert!(
            matches!(a.verificar_sello(), Err(ErrorActa::RaizNoCoincide { .. })),
            "se alteró una marca MAC sellada y el acta siguió acreditándola"
        );
    }

    /// Mutante del OTRO campo v2 por su OTRA vía: la procedencia (`titulo_referencia`)
    /// no es de un `Elemento`, así que no entra en la raíz de Merkle pero sí en lo
    /// firmado → cae en `FirmaInvalida`, no en `RaizNoCoincide`. Dos campos nuevos,
    /// sus dos vías distintas (D33).
    #[test]
    fn alterar_la_procedencia_del_fijo_v2_la_invalida() {
        let mut a = acta_v2_del_vector();
        assert!(!a.adquisicion.titulo_referencia.is_empty(), "el fijo v2 debe traer procedencia");
        a.adquisicion.titulo_referencia = "Auto FALSO 9999".into();
        assert_eq!(a.verificar_sello(), Err(ErrorActa::FirmaInvalida));
    }

    /// **LA GARANTÍA QUE CIERRA EL RESIDUO.** Un acta de una versión que este binario
    /// NO conoce no puede terminar acusada de forjada, aunque su raíz no cuadre: el
    /// chequeo de versión corre ANTES que el de la raíz, así que el veredicto es «no
    /// sé leer esta versión» (`VersionNoSoportada`), nunca `RaizNoCoincide`. Se fuerza
    /// el peor caso —raíz deliberadamente rota— y se exige que el error sea de VERSIÓN.
    #[test]
    fn una_version_futura_no_se_lee_como_forjada() {
        let mut a = acta_v2_del_vector();
        a.formato = "tunjo/acta-v99".into();
        a.raiz_merkle = "00".repeat(32);
        match a.verificar_sello() {
            Err(ErrorActa::VersionNoSoportada { declarado, .. }) => {
                assert_eq!(declarado, "tunjo/acta-v99");
            }
            otro => panic!("una versión futura NO se reportó como VersionNoSoportada: {otro:?}"),
        }
    }

    /// La otra mitad de la discriminación (D23/D33): algo que NO es de la familia
    /// tunjo es `FormatoDesconocido`, no `VersionNoSoportada`. Una versión futura pide
    /// actualizar el verificador; un productor ajeno es basura, y se distinguen.
    #[test]
    fn un_formato_ajeno_es_desconocido_no_version() {
        let mut a = acta_v2_del_vector();
        a.formato = "otra-herramienta/acta-v1".into();
        assert!(matches!(a.verificar_sello(), Err(ErrorActa::FormatoDesconocido(_))));
    }

    /// Invariante 2 en el camino de versión: el `formato` es texto del JSON (lo elige
    /// quien entrega el acta), así que un escape de terminal dentro de él NO puede
    /// sobrevivir al mensaje de error —reescribiría el veredicto que lee una persona—.
    /// Se comprueba en las DOS variantes que lo imprimen, cada una con su control (el
    /// texto legible SÍ sigue, saneado a espacio, no borrado).
    #[test]
    fn el_formato_malicioso_no_reescribe_la_pantalla() {
        let mut a = acta_v2_del_vector();
        a.formato = "tunjo/acta-v9\u{1b}[2K9".into();
        let msg = a.verificar_sello().unwrap_err().to_string();
        assert!(!msg.contains('\u{1b}'), "el escape sobrevivió en VersionNoSoportada: {msg:?}");
        assert!(msg.contains("tunjo/acta-v9"), "el saneo se comió el formato entero: {msg:?}");

        let mut b = acta_v2_del_vector();
        b.formato = "ajeno\u{1b}[2Kfalso".into();
        let msg_b = b.verificar_sello().unwrap_err().to_string();
        assert!(!msg_b.contains('\u{1b}'), "el escape sobrevivió en FormatoDesconocido: {msg_b:?}");
        assert!(msg_b.contains("ajeno"), "el saneo se comió el formato ajeno entero: {msg_b:?}");
    }

    /// **EL MECANISMO DEL RESIDUO, reproducido por su vía real.** Demuestra POR QUÉ
    /// hizo falta la negociación: un binario viejo (que no declara los campos v2)
    /// deserializa un acta v2 descartándolos en silencio —`serde` ignora lo que no
    /// conoce, no hay `deny_unknown_fields`—, y al recalcular la raíz sin ellos obtiene
    /// OTRA distinta de la declarada. Ese es el `RaizNoCoincide` con el que un acta
    /// buena se leía como forjada. Se simula el binario viejo con structs recortadas y
    /// la MISMA lógica de hoja de Merkle (`merkle::hoja` sobre el elemento serializado).
    #[test]
    fn un_binario_viejo_recalcula_otra_raiz_de_un_acta_v2() {
        use serde::Deserialize;

        #[derive(Serialize, Deserialize)]
        struct ElementoViejo {
            ruta: String,
            tipo: String,
            bytes: u64,
            sha256: String,
            modificado_utc: String,
            estado: String,
            #[serde(default, skip_serializing_if = "String::is_empty")]
            metodo_huella: String,
        }
        #[derive(Deserialize)]
        struct ActaVieja {
            elementos: Vec<ElementoViejo>,
            raiz_merkle: String,
        }

        let vieja: ActaVieja = serde_json::from_str(ACTA_V2_2026)
            .expect("el binario viejo deserializa el acta v2 ignorando lo que no conoce");
        let hojas: Vec<[u8; 32]> = vieja
            .elementos
            .iter()
            .map(|e| merkle::hoja(&serde_json::to_vec(e).expect("serializable")))
            .collect();
        let recalculada = hex(&merkle::raiz(&hojas).expect("hay elementos"));
        assert_ne!(
            recalculada, vieja.raiz_merkle,
            "si coincidieran, los campos v2 no entrarían en la raíz y el residuo no existiría: \
             el binario viejo recalcula OTRA raíz, y por eso un acta v2 marcada v1 se leería como forjada"
        );
    }

    /// Solo para GENERAR el fijo v2. Ignorada, como su hermana de la v1: se corre a
    /// mano y solo cuando la decisión de fijar la v2 ya está tomada.
    ///
    ///     cargo test --lib vector_de_firma::generar_el_acta_fija_v2 -- --ignored --nocapture
    #[test]
    #[ignore = "genera tests/fijos/acta_v2_2026.json; no mide nada"]
    fn generar_el_acta_fija_v2() {
        use crate::clave;

        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("de_2026.clave");
        std::fs::write(&ruta, STANDARD.decode(CLAVE_2026_B64).expect("base64")).unwrap();
        let sk = clave::cargar(&ruta, "contrasena-de-prueba-larga-2026").expect("abrir la clave");

        let mut a = Acta {
            formato: FORMATO.to_string(),
            caso: Caso {
                referencia: "VECTOR-2026-V2".into(),
                descripcion: "acta fija v2 del banco: no corresponde a ningún peritaje real".into(),
            },
            perito: Perito {
                nombre: "Perito del vector".into(),
                identificacion: "CC 00000000".into(),
                clave_publica: STANDARD.encode(sk.verifying_key().to_bytes()),
            },
            adquisicion: Adquisicion {
                origen: "/vector/2026-v2".into(),
                metodo: "copia lógica en solo lectura".into(),
                reloj: Reloj {
                    inicio_utc: "2026-08-12T12:00:00Z".into(),
                    fin_utc: "2026-08-12T12:00:01Z".into(),
                    desfase_local_utc: "-05:00".into(),
                    verificacion: "NO VERIFICADO".into(),
                },
                herramienta: "tunjo (vector fijo v2)".into(),
                algoritmos: ALGORITMOS.into(),
                // LLENOS a propósito: la v2 se distingue por traer procedencia.
                fundamento: "inspección extraprocesal (CGP art. 189)".into(),
                titulo_referencia: "Auto 2026-00123 del Juzgado 5 Civil de Medellín".into(),
            },
            elementos: vec![
                Elemento {
                    ruta: "prueba.txt".into(),
                    tipo: "archivo".into(),
                    bytes: 12,
                    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
                    modificado_utc: "2026-08-12T11:00:00Z".into(),
                    // LLENOS: las marcas MAC son lo nuevo de la v2.
                    accedido_utc: "2026-08-12T10:30:00Z".into(),
                    creado_utc: "2026-08-01T09:00:00Z".into(),
                    estado: "leido".into(),
                    metodo_huella: String::new(),
                },
                Elemento {
                    ruta: "carpeta".into(),
                    tipo: "directorio".into(),
                    bytes: 0,
                    sha256: String::new(),
                    modificado_utc: "2026-08-12T11:00:00Z".into(),
                    // Un directorio deja el atime VACÍO a propósito (el recorrido lo
                    // tocaría); el btime puede existir.
                    accedido_utc: String::new(),
                    creado_utc: "2026-08-01T09:00:00Z".into(),
                    estado: "directorio".into(),
                    metodo_huella: String::new(),
                },
            ],
            raiz_merkle: String::new(),
            firma: None,
            sello_tiempo: None,
        };
        a.fijar_raiz().expect("raíz");
        let sig = sk.sign(&a.bytes_canonicos());
        a.firma = Some(Firma { algoritmo: ALGORITMOS.into(), valor: STANDARD.encode(&sig) });
        assert_eq!(a.verificar_sello(), Ok(()), "el vector v2 recién generado no verifica");

        let json = serde_json::to_string_pretty(&a).unwrap();
        let destino = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fijos/acta_v2_2026.json");
        std::fs::write(&destino, json).unwrap();
        println!("escrito: {}", destino.display());
    }

    /// Copia del literal de `clave::pruebas`, que es privado. Se comprueba que
    /// siguen siendo el mismo en `el_vector_usa_la_clave_del_otro_vector`.
    const CLAVE_2026_B64: &str = "\
        UVVJUAEAAABUVU5KT0tFWUA/+ZpR6d66bAvTLr/xrw3/pfDMWJ+yyS5kJwaE6DX6xHAj8e6fTuMA\
        AQAAAAAAAwAAAAGZrrVXgMy1Hia5E4nudX+i8c9GMx7SN10BP1gxEFC8VgnIPiDueda2lUk8YmJa\
        WE9ZdnGpQCsqmc9Ufsgi8eJ1QL1CQD3Zay11lejJufXpVkHmiUQni9BpKgKPFoeml8TpzwlS/uMr\
        WucjEWapCt3mpjssX7mUTwbImQrM5mHLSvVbzIBPcnWtoulIPOyg1ByOJclxbEnTG6XjGZd0I+B6\
        saXxmdQ1lzGqtlQW/UaFC9WMeDuwKZ2M7NNeG7wx0LkHc3lpunrR5MZfszohd3PF5ymJBd9IF0pg\
        Z5gkCqpb0A==";
}

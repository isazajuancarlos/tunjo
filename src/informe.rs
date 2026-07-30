// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! El acta en la forma en que se anexa a un dictamen: legible por un juez.
//!
//! El JSON es lo que se firma y lo que se verifica; este documento es lo que se
//! lee. Por eso se genera SIEMPRE desde el JSON y nunca al revés: si alguien
//! edita el Markdown, el sello sigue estando sobre el JSON y la diferencia se
//! nota.
//!
//! # Por qué este módulo está construido así
//!
//! Seis pasadas de `security-review` sobre esta rama dieron 2, 2, 3, 5, 6 y 9
//! defectos —el ritmo SUBIENDO— y unos veintidós de los veintisiete estaban en
//! esta capa. Todos de dos clases:
//!
//! 1. **Una frase que afirmaba algo sin que nadie lo hubiera comprobado**, porque
//!    la condición (`if verificada.es_valida()`) se ponía a mano, frase a frase, y
//!    siempre faltaba una: §4 y §5 mientras §6 ya estaba puesta, el numeral 1
//!    mientras el 4 sí, el bloque de ilegibles mientras los demás sí.
//! 2. **Un campo del JSON interpolado sin neutralizar**, porque el escapado se
//!    llamaba a mano, sitio a sitio, y siempre faltaba uno.
//!
//! Parchear no converge, y hay prueba: dos de los seis defectos de la quinta ronda
//! los causaron los arreglos de la cuarta, y uno de los nueve de la sexta era un
//! arreglo de la quinta que solo cerró la mitad del caso. Así que las dos clases se
//! hacen **inexpresables**:
//!
//! - **Ningún método de [`Documento`] acepta un `&str`.** La prosa entra como
//!   [`Fijo`], [`Segun`] o [`PorFecha`] —constantes declaradas todas en [`dicho`]—
//!   y los datos del acta entran como [`Dato`] o [`EnValla`], que **escapan o
//!   validan la forma al construirse**. Olvidar el escapado deja de ser un
//!   descuido posible: no compila.
//! - **Toda frase que habla de ESTA acta lleva su condición en el tipo.** Un
//!   [`Segun<C>`] no se puede emitir sin decir de qué depende, y lleva a la fuerza
//!   las DOS versiones: la que se dice cuando la comprobación salió bien y la que
//!   se dice cuando no. El silencio no es una opción —un acta que no verifica es
//!   precisamente la que alguien querría presentar como buena—, así que donde no
//!   se puede afirmar hay que decir que no se puede, y el tipo lo exige.
//! - Donde la decisión no es binaria (§6), se deriva un [`Fecha`] y se despacha con
//!   un `match` exhaustivo: **un estado nuevo sin su texto no compila.**
//!
//! # Lo que esto NO garantiza
//!
//! El compilador no lee español. Si alguien escribe una afirmación dentro de un
//! [`Fijo`], sale sin respaldo. Lo que el diseño consigue es que **revisar esta
//! capa sea leer una lista de constantes**, cada una con su condición al lado, en
//! vez de quinientas líneas de `push_str` donde la condición estaba a veinte
//! líneas de la frase que sostenía.

use std::marker::PhantomData;

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use crate::acta::{Acta, Elemento, hex};

// ==========================================================================
// 1. Neutralización: la única puerta por la que entra texto del acta
// ==========================================================================

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

/// ¿Son 64 dígitos hexadecimales, es decir, la forma de un SHA-256?
fn es_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
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

/// Texto plano para la SALIDA POR PANTALLA, no para el documento.
///
/// El acta legible se escapaba y la salida del programa no, y ahí vive el
/// veredicto que lee una persona: un `\u{1b}[2K` dentro de un campo del JSON borra
/// la línea que acaba de imprimirse y pinta encima «SELLO VÁLIDO». El código de
/// salida seguía siendo 1, pero nadie frente a un prompt lo mira. Cuarta revisión.
pub fn plano(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// Cuántos elementos tienen contenido **verificable**, contado por la EVIDENCIA.
///
/// Por la huella y no por el estado declarado: `estado == "leido"` lo escribe quien
/// entrega el acta, y un elemento sin `sha256` no está atado a nada —`contrastar`
/// lo llama `NoVerificable`— pero se contaba como verificable y el numeral 1 del §8
/// acreditaba su contenido. Tercer defecto de la sexta ronda. Vive aquí, y no
/// duplicado en cada llamante, porque la definición de «verificable» es UNA.
pub fn verificables(elementos: &[Elemento]) -> usize {
    elementos.iter().filter(|e| e.estado == "leido" && !e.sha256.is_empty()).count()
}

/// Un valor que viene del JSON, ya neutralizado.
///
/// Es el ÚNICO tipo que [`Documento`] acepta para texto que no escribimos nosotros,
/// y sus constructores escapan. No hay `From<&str>`, ni `Display`, ni campo público
/// que lo salte: si un valor del acta llegó al documento, pasó por aquí.
///
/// Ese es todo el truco contra la segunda clase de defecto. Antes había que
/// acordarse de llamar a `escapar` en cada interpolación, y en cinco rondas siempre
/// faltó una; ahora no hay ninguna interpolación posible sin construir un `Dato`.
pub struct Dato(String);

impl Dato {
    /// Un valor que se interpola DENTRO de una línea.
    pub fn linea(s: &str) -> Dato {
        Dato(escapar(s))
    }

    /// El único campo que se interpola al PRINCIPIO de una línea.
    ///
    /// `caso.descripcion` va a columna cero tras una línea en blanco, y ahí cuatro
    /// espacios abren un bloque de código indentado — que no forja una sección,
    /// pero deja el párrafo del acta en monoespaciado sin que nadie lo haya pedido.
    /// La puntuación ya la neutraliza [`escapar`]; lo único que añade esto es
    /// quitar la sangría inicial.
    pub fn bloque(s: &str) -> Dato {
        Dato(escapar(s.trim_start()))
    }

    /// Un número que contamos nosotros: no hay nada que neutralizar.
    pub fn numero(n: u64) -> Dato {
        Dato(n.to_string())
    }

    /// El valor, o un guion si viene vacío. Para las celdas del anexo.
    pub fn o_guion(s: &str) -> Dato {
        if s.is_empty() { Dato("—".into()) } else { Dato::linea(s) }
    }

    /// El valor ya neutralizado. Lo lee el acumulador, que está en otro módulo.
    fn texto(&self) -> &str {
        &self.0
    }
}

/// Un valor que va DENTRO de una valla de código.
///
/// Ahí el escapado **no vale nada**: el renderizador no consume las barras
/// invertidas —así que se verían— y un acento grave en el valor cierra la valla
/// antes de tiempo. Por eso este tipo no se puede construir con texto libre: solo
/// con valores cuya FORMA se comprobó, o que produce esta misma casa.
pub struct EnValla(String);

impl EnValla {
    /// 64 dígitos hexadecimales, o nada.
    ///
    /// Un valor que no lo es no entra en la valla: quien llama lo dice y lo imprime
    /// escapado como texto corriente. Meter dentro de una valla algo que no se pudo
    /// comprobar es exactamente el hueco que la sexta ronda encontró con
    /// `acta_sha256`.
    pub fn hex64(s: &str) -> Option<EnValla> {
        es_hex64(s).then(|| EnValla(s.to_string()))
    }

    /// La huella SHA-256 de un valor en base64.
    ///
    /// La produce [`huella`], así que lo que entra en la valla son dígitos
    /// hexadecimales y espacios que escribimos nosotros — nada del acta llega
    /// entero. Si el base64 no decodifica, dice que es ilegible.
    pub fn huella_de(b64: &str) -> EnValla {
        EnValla(huella(b64))
    }

    /// El valor de forma comprobada. Lo lee el acumulador, que está en otro módulo.
    fn texto(&self) -> &str {
        &self.0
    }
}

// ==========================================================================
// 2. El respaldo: lo que el VERIFICADOR estableció
// ==========================================================================

/// Lo que el verificador concluyó sobre el sello de tiempo, que es lo único que
/// este documento puede afirmar sobre la fecha.
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

/// El único juicio que este documento puede hacer sobre la FECHA.
///
/// Se deriva del veredicto del verificador en UN sitio ([`Respaldo::nuevo`]) y se
/// despacha con un `match` exhaustivo: añadir un estado sin escribir su texto no
/// compila. Antes eran tres `if` anidados dentro de un brazo de `match`, y la
/// afirmación más fuerte del documento —«certificó»— se le arrancó a la
/// herramienta en tres rondas distintas por tres caminos distintos.
pub enum Fecha {
    /// Autoridad **acreditada contra un ancla** y acta íntegra. Es lo único que
    /// sostiene «certificó» y «fecha cierta».
    Cierta,
    /// Token correctamente firmado y acta íntegra, pero **sin ancla**: un
    /// certificado autofirmado emitido hace un minuto produce este mismo
    /// resultado, así que no acredita de quién viene la fecha.
    FirmaSinAutoridad,
    /// Token correctamente firmado, pero la firma del acta NO verifica. El sello
    /// cubre el VALOR del campo `firma`, no el cuerpo del acta: hablar de «la
    /// firma de esta acta» no significaría nada.
    SoloElCampoDeFirma,
    /// Vino un sello y no se sostiene.
    NoSeSostiene,
    /// No hay sello de tiempo de un tercero.
    Ausente,
}

/// Lo que el verificador estableció, reducido a los hechos que el documento puede
/// invocar.
///
/// Se construye en un solo sitio y **nunca desde el JSON**. Sus campos son
/// privados: la única manera de consultarlo es a través de una [`Condicion`], que
/// es lo que obliga a que cada afirmación diga de qué depende.
pub struct Respaldo {
    integra: bool,
    /// La identidad de la autoridad quedó acreditada contra un ancla. Va aparte de
    /// [`Fecha`] **a propósito**: es un hecho sobre el TOKEN y no sobre el acta, y
    /// mezclarlos hacía que un acta rota con un sello perfectamente anclado dijera
    /// que no se había comprobado a quién pertenece el certificado — que es falso.
    anclada: bool,
    fecha: Fecha,
}

impl Respaldo {
    fn nuevo(verificada: &ActaVerificada, sello: &SelloVerificado) -> Respaldo {
        let integra = matches!(verificada, ActaVerificada::Valida);
        let anclada = matches!(sello, SelloVerificado::Valido(_, c) if c.acredita_autoridad());
        // El ÚNICO sitio donde se combinan las dos comprobaciones. Antes esta
        // lógica estaba repartida entre el brazo `Valido` de §6 y el numeral 4 del
        // §8, cada uno con su condición: el numeral 4 solo exigía la autoridad
        // acreditada, así que con el acta rota remitía a un §6 que decía otra cosa.
        let fecha = match sello {
            SelloVerificado::Ausente => Fecha::Ausente,
            SelloVerificado::Invalido(_) => Fecha::NoSeSostiene,
            SelloVerificado::Valido(_, _) if !integra => Fecha::SoloElCampoDeFirma,
            SelloVerificado::Valido(_, c) if c.acredita_autoridad() => Fecha::Cierta,
            SelloVerificado::Valido(_, _) => Fecha::FirmaSinAutoridad,
        };
        Respaldo { integra, anclada, fecha }
    }
}

/// Una comprobación de la que depende una afirmación del documento.
///
/// Los tipos que la implementan son marcas sin valor: existen para viajar en el
/// tipo de un [`Segun`] y que el compilador exija que quien escribe la frase diga
/// de qué depende. Su único evaluador es el [`Respaldo`].
pub trait Condicion {
    /// Lo evalúa [`Documento::segun`]; no se llama a mano.
    fn se_cumple(r: &Respaldo) -> bool;
}

/// La firma del acta verifica contra la clave pública que la propia acta declara.
pub struct ActaIntegra;
impl Condicion for ActaIntegra {
    fn se_cumple(r: &Respaldo) -> bool {
        r.integra
    }
}

/// Una autoridad **acreditada** certificó la fecha, **y** el acta verifica.
///
/// Es la condición de la afirmación más fuerte del documento, y por eso la
/// comparten §6 y el numeral 4 del §8: cuando cada una tenía la suya, el numeral 4
/// remitía a un §6 que, con el acta rota, no decía lo que el numeral 4 daba por
/// dicho. Una condición compartida no se puede desincronizar.
pub struct FechaCierta;
impl Condicion for FechaCierta {
    fn se_cumple(r: &Respaldo) -> bool {
        matches!(r.fecha, Fecha::Cierta)
    }
}

/// El certificado del firmante encadena hasta un ancla que aportó el verificador.
///
/// Es un hecho **sobre el token**, y por eso no exige que el acta verifique: el
/// bloque que describe el alcance de la comprobación del sello habla de lo que la
/// herramienta hizo con ese token, no de la firma del acta. Confundirlos hace que
/// un acta rota con un sello impecablemente anclado diga que no se comprobó a quién
/// pertenece el certificado, y eso sería falso — la clase exacta de frase que este
/// módulo existe para impedir, esta vez en la dirección contraria a la habitual.
pub struct AutoridadAcreditada;
impl Condicion for AutoridadAcreditada {
    fn se_cumple(r: &Respaldo) -> bool {
        r.anclada
    }
}

// ==========================================================================
// 3. Los tres tipos de prosa, y lo que cada uno garantiza
// ==========================================================================

/// Texto fijo que **no habla de esta acta**: encabezados, etiquetas, el marco
/// normativo, las instrucciones para verificar.
///
/// Es la única puerta por la que entra prosa sin condición, y está separada
/// precisamente para que se vea. Si una frase dice algo de ESTA acta, no va aquí:
/// va en un [`Segun`] o en un [`PorFecha`]. El compilador no puede comprobarlo —no
/// lee español— pero la revisión sí, porque son una lista corta y nombrada.
///
/// Puede llevar huecos `{}` para [`Dato`]s: una etiqueta con su valor transcribe,
/// no afirma.
pub struct Fijo(&'static str);

impl Fijo {
    /// El texto, para que las pruebas casen contra ESTA constante.
    pub fn texto(&self) -> &'static str {
        self.0
    }
}

/// Una afirmación sobre ESTA acta, con la comprobación que la sostiene escrita en
/// su tipo.
///
/// Lleva las DOS versiones a la fuerza. No se puede escribir la afirmación y
/// olvidar la contraparte, porque el constructor exige ambas: donde no se puede
/// afirmar, el documento dice que no se puede.
pub struct Segun<C: Condicion> {
    con: &'static str,
    sin: &'static str,
    _c: PhantomData<C>,
}

impl<C: Condicion> Segun<C> {
    const fn nueva(con: &'static str, sin: &'static str) -> Segun<C> {
        Segun { con, sin, _c: PhantomData }
    }

    /// Lo que se dice cuando la comprobación salió bien.
    ///
    /// Es público para que las pruebas casen contra ESTA cadena y no contra una
    /// copia. Una prueba que repite el texto se pone verde para siempre en cuanto
    /// alguien reflúa el párrafo —y una de las de esta rama tenía el salto de línea
    /// dentro de la aserción—; casando contra la constante, un reescrito mueve los
    /// dos lados a la vez. Noveno hallazgo de la sexta ronda.
    pub fn con(&self) -> &'static str {
        self.con
    }

    /// Lo que se dice cuando la comprobación no se hizo o falló.
    pub fn sin(&self) -> &'static str {
        self.sin
    }
}

/// ¿Dice el documento lo que dice esta plantilla?
///
/// Casa tolerando los huecos `{}`: cada trozo entre huecos tiene que aparecer, y en
/// ese orden. Existe para que las pruebas apunten a la CONSTANTE de [`dicho`] y no a
/// una copia del texto. Una copia se pone verde para siempre en cuanto alguien
/// reflúa el párrafo —y una prueba de esta rama tenía el salto de línea dentro de la
/// aserción, así que bastaba reflujar para que dejara de comprobar nada—; casando
/// contra la constante, un reescrito mueve los dos lados a la vez.
pub fn dice(md: &str, plantilla: &str) -> bool {
    let mut resto = md;
    for trozo in plantilla.split("{}") {
        match resto.find(trozo) {
            Some(i) => resto = &resto[i + trozo.len()..],
            None => return false,
        }
    }
    true
}

/// Una afirmación cuya condición es un estado de [`Fecha`].
///
/// No lleva contraparte porque el `match` exhaustivo ya la exige: no hay estado sin
/// su texto, y añadir uno nuevo no compila hasta que se escribe el suyo. Es la
/// forma que toman las afirmaciones cuando la decisión no es binaria.
pub struct PorFecha(&'static str);

impl PorFecha {
    /// El texto, para que las pruebas casen contra ESTA constante.
    pub fn texto(&self) -> &'static str {
        self.0
    }
}

// ==========================================================================
// 4. El documento
// ==========================================================================

/// El acumulador del Markdown, tras una frontera que el compilador sí vigila.
///
/// Vive en su propio módulo **a propósito**. El `String` es privado de `papel`, así
/// que las funciones que arman el documento —que están fuera— no pueden escribir en
/// él: tienen que pasar por estos métodos, y **ninguno acepta un `&str`**. Mientras
/// `Documento` estuvo en el mismo módulo que el armado, «no se interpola sin
/// escapar» era una convención; aquí es una regla de visibilidad.
mod papel {
    use super::{Condicion, Dato, EnValla, Fijo, PorFecha, Respaldo, Segun};

    pub struct Documento {
        md: String,
        respaldo: Respaldo,
    }

    impl Documento {
        pub fn nuevo(respaldo: Respaldo) -> Documento {
            Documento { md: String::with_capacity(8 * 1024), respaldo }
        }

        /// El respaldo, para que el armado pueda hacer su `match` sobre la fecha.
        /// Solo de lectura: nadie lo cambia a mitad de documento.
        pub fn respaldo(&self) -> &Respaldo {
            &self.respaldo
        }

        /// El documento terminado. Consume: no se sigue escribiendo después.
        pub fn terminar(self) -> String {
            self.md
        }

        /// Rellena los huecos `{}` de una plantilla con datos ya neutralizados.
        ///
        /// Se parte la PLANTILLA y se intercalan los datos, así que un `{}` que
        /// viniera dentro de un dato no puede abrir un hueco nuevo — y de todas
        /// formas no puede venir: el escapado convierte las llaves en `\{` y `\}`.
        ///
        /// Si las cuentas no cuadran, **revienta**. Es un defecto de programación,
        /// no un dato ausente del acta, y el banco de combinaciones renderiza todas
        /// las ramas: se muere en las pruebas, no en producción. Emitir la frase con
        /// el hueco a medias sería exactamente el valor de relleno que la directiva
        /// 20 prohíbe.
        fn emitir(&mut self, plantilla: &'static str, datos: &[&Dato]) {
            let mut trozos = plantilla.split("{}");
            self.md.push_str(trozos.next().unwrap_or_default());
            let mut puestos = 0;
            for trozo in trozos {
                let d = datos.get(puestos).unwrap_or_else(|| {
                    panic!("faltan datos para los huecos de la plantilla: {plantilla:?}")
                });
                self.md.push_str(d.texto());
                self.md.push_str(trozo);
                puestos += 1;
            }
            assert_eq!(
                puestos,
                datos.len(),
                "sobran datos para los huecos de la plantilla: {plantilla:?}"
            );
        }

        /// Texto que no habla de esta acta.
        pub fn fijo(&mut self, t: &Fijo) {
            self.emitir(t.texto(), &[]);
        }

        /// Texto que no habla de esta acta, con datos del acta transcritos.
        pub fn fijo_con(&mut self, t: &Fijo, datos: &[&Dato]) {
            self.emitir(t.texto(), datos);
        }

        /// Una afirmación sin datos interpolados.
        pub fn segun<C: Condicion>(&mut self, a: &Segun<C>) {
            self.segun_con(a, &[], &[]);
        }

        /// Una afirmación cuyas versiones interpolan datos.
        ///
        /// Cada versión declara los suyos y solo se piden los de la que se emite: la
        /// afirmación positiva y la negativa casi nunca dicen lo mismo ni con lo
        /// mismo —la negativa suele llevar el motivo—, así que forzarlas a la misma
        /// forma sería obligar a inventar texto.
        pub fn segun_con<C: Condicion>(&mut self, a: &Segun<C>, con: &[&Dato], sin: &[&Dato]) {
            if C::se_cumple(&self.respaldo) {
                self.emitir(a.con(), con);
            } else {
                self.emitir(a.sin(), sin);
            }
        }

        /// Una afirmación elegida por un `match` exhaustivo sobre `Fecha`.
        pub fn por_fecha(&mut self, t: &PorFecha, datos: &[&Dato]) {
            self.emitir(t.texto(), datos);
        }

        /// Un valor dentro de una valla de código.
        pub fn valla(&mut self, v: &EnValla) {
            self.md.push_str("```\n");
            self.md.push_str(v.texto());
            self.md.push_str("\n```\n\n");
        }

        /// Una línea en blanco. Es lo único que se puede escribir sin plantilla, y
        /// no lleva texto ninguno.
        pub fn salto(&mut self) {
            self.md.push('\n');
        }
    }
}

use papel::Documento;

// ==========================================================================
// 5. Lo que el documento dice
// ==========================================================================

/// Todo lo que el documento dice, en un solo sitio y con su condición al lado.
///
/// Revisar esta capa es leer esta lista. Cada [`Segun`] lleva en su tipo la
/// comprobación que lo sostiene y, obligatoriamente, lo que se dice cuando esa
/// comprobación no se hizo o falló; cada [`PorFecha`] corresponde a un estado del
/// `match` exhaustivo; y los [`Fijo`] son —tienen que ser— texto que no habla de
/// esta acta concreta.
pub mod dicho {
    use super::{ActaIntegra, AutoridadAcreditada, Fecha, FechaCierta, Fijo, PorFecha, Segun};

    // ------------------------------------------------------------- cabecera
    pub const TITULO: Fijo = Fijo("# Acta de sellado de evidencia digital\n\n");
    pub const REFERENCIA: Fijo = Fijo("**Referencia:** {}\n\n");
    pub const DESCRIPCION: Fijo = Fijo("{}\n\n");

    // ------------------------------------------------------------ 1. perito
    pub const SEC_PERITO: Fijo = Fijo("## 1. Perito\n\n");
    pub const PERITO_NOMBRE: Fijo = Fijo("- **Nombre:** {}\n");
    pub const PERITO_ID: Fijo = Fijo("- **Identificación:** {}\n");
    pub const PERITO_CLAVE: Fijo =
        Fijo("- **Clave pública de verificación** — huella SHA-256:\n\n");

    // ------------------------------------------------------- 2. adquisición
    pub const SEC_ADQUISICION: Fijo = Fijo("## 2. Método de adquisición\n\n");
    pub const ADQ_ORIGEN: Fijo = Fijo("- **Origen:** {}\n");
    pub const ADQ_METODO: Fijo = Fijo("- **Método:** {}\n");
    pub const ADQ_HERRAMIENTA: Fijo = Fijo("- **Herramienta:** {}\n");
    pub const ADQ_ALGORITMOS: Fijo = Fijo("- **Algoritmos:** {}\n");

    /// Se ATRIBUYE en vez de afirmarse, y por eso es un `Fijo` y no un `Segun`.
    ///
    /// El acceso de solo lectura es una propiedad de Tunjo cuando ÉL hizo la
    /// adquisición, no un hecho que este documento pueda afirmar de un acta que se
    /// limita a leer: si la escribió otra herramienta, «la herramienta» es la que
    /// diga el campo de arriba. Misma clase que el «no han cambiado desde entonces»
    /// de la ronda anterior. Quinta revisión.
    pub const ADQ_ACCESO: Fijo = Fijo(
        "- **Acceso declarado:** de solo lectura. Tunjo no escribe dentro del origen \n\
         cuando es él quien adquiere; para un acta emitida por otra herramienta, esto \n\
         es lo que declara el perito, no algo que este documento haya comprobado.\n\n",
    );

    pub const SEC_RELOJ: Fijo = Fijo("### Registro horario\n\n");
    pub const RELOJ_INICIO: Fijo = Fijo("- **Inicio (UTC):** {}\n");
    pub const RELOJ_FIN: Fijo = Fijo("- **Fin (UTC):** {}\n");
    pub const RELOJ_DESFASE: Fijo = Fijo("- **Desfase local respecto de UTC:** {}\n");
    pub const RELOJ_CONTRASTE: Fijo = Fijo("- **Contraste del reloj:** {}\n\n");

    // ----------------------------------------------------------- 3. resumen
    pub const SEC_RESUMEN: Fijo = Fijo("## 3. Resumen\n\n");
    pub const TABLA_RESUMEN: Fijo =
        Fijo("| Elementos | Leídos | Ilegibles | Bytes |\n|---|---|---|---|\n");
    pub const FILA_RESUMEN: Fijo = Fijo("| {} | {} | {} | {} |\n\n");

    pub const ILEGIBLES_AVISO: Fijo = Fijo(
        "> **Elementos que no pudieron leerse.** Constan en el acta y NO están\n\
         > cubiertos por ninguna afirmación de integridad.\n",
    );

    /// Lo que consta de un elemento ilegible — y **solo** si el acta verifica.
    ///
    /// Antes decía «de ellos solo se acredita que existían y que la lectura falló»,
    /// y era falso por dos motivos que encontró la sexta revisión. Uno: no estaba
    /// gateado por el veredicto, así que un acta que no verifica afirmaba haber
    /// acreditado algo. Dos: `ERROR:` incluye «no such file or directory», así que
    /// ni en el caso válido se acredita la EXISTENCIA — lo único que consta es que
    /// el perito registró esa ruta y que la lectura falló. Afirmar la existencia de
    /// lo que el propio registro dice que no estaba es la clase de frase que se cae
    /// en un contrainterrogatorio.
    pub const ILEGIBLES_QUE_CONSTA: Segun<ActaIntegra> = Segun::nueva(
        "> Consta que el perito registró esa ruta y que la lectura falló; NO se\n\
         > acredita que el elemento existiera ni cuál era su contenido.\n\n",
        "> Y como la firma de esta acta no verifica (numeral 5), tampoco consta\n\
         > que el registro de estas rutas sea el que el perito hizo.\n\n",
    );

    /// Sin tramo de código: dentro de uno el escapado no vale nada (ni barras ni
    /// entidades) y un acento grave en la ruta cierra el tramo antes de tiempo. Se
    /// quitó en los demás sitios y este se escapó — precisamente el que ninguna
    /// prueba renderizaba. Quinta revisión.
    pub const ILEGIBLE_ITEM: Fijo = Fijo("> - {} — {}\n");

    // -------------------------------------------------------------- 4. raíz
    pub const SEC_RAIZ: Fijo = Fijo("## 4. Raíz de integridad\n\n");

    /// La afirmación de integridad, y su negativa.
    ///
    /// En la versión negativa **no se imprime la raíz declarada acompañada de la
    /// frase que le da sentido**: sería exactamente la afirmación que acaba de
    /// fallar. El hueco de la negativa es el motivo.
    pub const RAIZ: Segun<ActaIntegra> = Segun::nueva(
        "Raíz del árbol de Merkle construido sobre los elementos listados en el\n\
         anexo. Cualquier cambio en un byte, en una ruta o en el orden produce una\n\
         raíz distinta.\n\n",
        "**ESTA ACTA NO VERIFICA.** No se afirma integridad de nada.\n\n\
         Motivo: {}\n\n\
         La raíz que el archivo declara está en el JSON, y NO corresponde a lo\n\
         que el archivo contiene, o su firma no es de quien dice ser. Este\n\
         documento no acredita nada; sirve para ver qué se pretendía acreditar.\n\n",
    );

    /// Cuando la raíz declarada no tiene forma de SHA-256 no entra en la valla: se
    /// dice y se imprime escapada como texto.
    pub const RAIZ_SIN_FORMA: Fijo =
        Fijo("**La raíz declarada no tiene la forma de un SHA-256:** {}\n\n");

    // ------------------------------------------------------------- 5. firma
    pub const SEC_FIRMA: Fijo = Fijo("## 5. Firma\n\n");
    pub const FIRMA_ALGORITMO: Fijo = Fijo("- **Algoritmo:** {}\n");

    pub const FIRMA_COBERTURA: Segun<ActaIntegra> = Segun::nueva(
        "- **Cobertura:** la totalidad del acta en formato JSON, incluidos el\n\
        \x20 listado de elementos y la raíz. **Comprobada.**\n\n",
        "- **Cobertura:** NINGUNA COMPROBADA. Esta firma **no verifica**\n\
        \x20 contra la clave pública que el propio acta declara, así que no\n\
        \x20 cubre el listado de elementos ni la raíz.\n\n",
    );

    pub const FIRMA_HUELLA: Fijo = Fijo("Huella SHA-256 de la firma:\n\n");
    pub const FIRMA_NOTA: Fijo = Fijo(
        "> La firma y la clave completas están en el archivo JSON, no en este\n\
         > documento: impresas ocuparían cientos de páginas que nadie cotejaría.\n\
         > **La verificación se hace sobre el JSON**; este documento es para leer,\n\
         > no para verificar.\n\n",
    );
    pub const FIRMA_AUSENTE: Fijo =
        Fijo("**ACTA SIN FIRMAR.** No acredita nada mientras no se selle.\n\n");

    // ------------------------------------------------------ 6. fecha cierta
    pub const SEC_FECHA: Fijo = Fijo("## 6. Fecha cierta\n\n");

    /// La afirmación más fuerte del documento. Solo con la autoridad acreditada
    /// **y** el acta íntegra: es lo que exige [`FechaCierta`].
    pub const FECHA_CIERTA: PorFecha = PorFecha(
        "Una autoridad de sellado independiente certificó que la firma de esta \n\
         acta ya existía el **{}**.\n\n",
    );

    /// Sin ancla no se escribe «certificó» ni «fecha cierta»: la firma es válida,
    /// pero un autofirmado emitido hace un minuto produce lo mismo.
    pub const FECHA_SIN_AUTORIDAD: PorFecha = PorFecha(
        "El sello de esta acta lleva una **firma válida** que dice que la firma \n\
         del acta ya existía el **{}** — pero su autoridad **NO está \n\
         acreditada**: el acta se verificó sin aportar la raíz de la autoridad \n\
         (`--tsa-ca`), y sin eso un certificado autofirmado produciría este \n\
         mismo resultado. Por eso este documento no afirma fecha cierta.\n\n",
    );

    /// El sello acredita que EL VALOR DEL CAMPO `firma` ya existía en esa fecha, no
    /// que el acta sea íntegra: son cosas distintas y el token no cubre el cuerpo
    /// del acta.
    pub const FECHA_SOLO_EL_CAMPO: PorFecha = PorFecha(
        "El acta trae un sello de tiempo con firma válida, **pero la firma del \n\
         acta no verifica** (numeral 5). Lo único que el sello dice es que el \n\
         valor guardado en el campo de firma ya existía en la fecha indicada; NO \n\
         dice que este acta sea íntegra, ni que su contenido estuviera cubierto \n\
         por nada, ni —si no se aportó `--tsa-ca`— de quién viene esa fecha.\n\n",
    );

    /// Nunca se calla: un acta con un sello que no se sostiene es precisamente la
    /// que alguien querría presentar como fechada.
    pub const FECHA_NO_SE_SOSTIENE: PorFecha = PorFecha(
        "**EL SELLO DE TIEMPO DE ESTA ACTA NO ES VÁLIDO.**\n\n\
         Motivo: {}\n\n\
         Este documento NO acredita ninguna fecha. Si el acta llegó con un\n\
         sello, no es el que dice ser.\n\n",
    );

    pub const FECHA_AUSENTE: PorFecha = PorFecha(
        "**Esta acta NO lleva sello de tiempo de un tercero.**\n\n\
         En consecuencia acredita **orden relativo**, no fecha cierta oponible:\n\
         la hora que consta es la del reloj de la máquina del perito. Para fecha\n\
         oponible hace falta el sello de una autoridad de estampado cronológico.\n\n",
    );

    pub const SELLO_AUTORIDAD: Fijo = Fijo("- **Autoridad que firma:** {}\n");
    pub const SELLO_POLITICA: Fijo = Fijo("- **Política de sellado:** {}\n");
    pub const SELLO_SERIE: Fijo = Fijo("- **Número de serie:** {}\n");
    pub const SELLO_PROTOCOLO: Fijo = Fijo(
        "- **Protocolo:** RFC 3161, el mismo documento normativo con el que\n\
        \x20 ONAC acredita el servicio de estampado cronológico en Colombia\n\
        \x20 (criterio CEA-3.0-07; art. 161.5 del Decreto Ley 019 de 2012).\n\n",
    );
    pub const SELLO_HUELLA: Fijo = Fijo("Huella SHA-256 del token:\n\n");

    pub const SELLO_ALCANCE: Fijo = Fijo(
        "> **Alcance de esta comprobación.** Esta herramienta verificó que el\n\
         > sello corresponde exactamente a la firma de esta acta, y que el token\n\
         > está **correctamente firmado**: un único firmante, su certificado\n\
         > dentro del token, con el uso `id-kp-timeStamping`, los atributos que\n\
         > atan la firma a este mismo sello, y la firma válida con esa clave.\n\
         >\n\
         > **No hizo validación PKI completa**: sin revocación (CRL/OCSP), sin\n\
         > restricciones de nombre y sin políticas de certificación.\n",
    );

    /// Cierra el alcance diciendo si la identidad de la autoridad se comprobó.
    ///
    /// Depende de [`AutoridadAcreditada`] y **no** de [`FechaCierta`]: describe lo
    /// que la herramienta hizo con el TOKEN, y eso no cambia porque la firma del
    /// acta verifique o no.
    ///
    /// Las dos versiones dicen algo: la positiva, que la cadena termina en el ancla
    /// aportada; la negativa, que no se comprobó a quién pertenece el certificado.
    /// El silencio en la rama buena sería una afirmación por omisión —el lector
    /// entendería que todo se comprobó— y es lo que este tipo existe para impedir.
    pub const SELLO_ACREDITACION: Segun<AutoridadAcreditada> = Segun::nueva(
        "> **Y sí comprobó a quién pertenece ese certificado**: la cadena del\n\
         > firmante termina en el ancla aportada con `--tsa-ca`.\n",
        "> **Y no comprobó a QUIÉN pertenece ese certificado**, porque no se\n\
         > aportó `--tsa-ca`: la identidad de la autoridad no está acreditada.\n",
    );

    pub const SELLO_COMO: Fijo = Fijo(
        "> Eso se hace con la herramienta estándar:\n\
         >\n\
         > ```bash\n\
         > openssl ts -verify -in sello.tsr -token_in -data firma.bin \\\n\
         >     -CAfile cadena_de_la_autoridad.pem\n\
         > ```\n\
         >\n\
         > El token completo está en el JSON para que cualquiera pueda hacerlo.\n\n",
    );

    // ---------------------------------------------------- 7. cómo verificar
    pub const SEC_VERIFICAR: Fijo = Fijo(
        "## 7. Cómo verificar esta acta\n\n\
         Cualquier tercero puede comprobarla sin intervención del perito y sin\n\
         software propietario: el verificador es libre y su código es público.\n\n\
         ```bash\n\
         tunjo verificar acta.json                 # firma y coherencia interna\n\
         tunjo verificar acta.json --origen RUTA   # además, contra el material en disco\n\
         ```\n\n",
    );

    // ----------------------------------------------------------- 8. alcance
    pub const SEC_ALCANCE: Fijo = Fijo(
        "## 8. Alcance y límites\n\n\
         Se deja constancia expresa de lo que esta acta **no** dice:\n\n",
    );

    /// Numeral 1. Lo que el acta acredita es el CONTENIDO EN EL MOMENTO de la
    /// adquisición. Que «no han cambiado desde entonces» es una afirmación sobre el
    /// disco de hoy, y `tunjo acta` no lee ningún disco: eso solo lo puede decir
    /// `tunjo verificar --origen`. Estaba escrito sin respaldo en TODOS los
    /// caminos, válidos incluidos. Cuarta revisión de seguridad.
    pub const ALCANCE_1: Segun<ActaIntegra> = Segun::nueva(
        "1. Acredita que los elementos listados tenían exactamente ese contenido en\n\
        \x20  el momento de la adquisición. Para contrastar contra el material de hoy,\n\
        \x20  `tunjo verificar --origen RUTA`, que es otra comprobación y la dice aparte.\n",
        "1. **NO acredita nada del contenido de los elementos listados**: la firma de\n\
        \x20  esta acta no verifica (numeral 5), así que el anexo es una lista sin\n\
        \x20  respaldo criptográfico.\n",
    );

    pub const ALCANCE_2_Y_3: Fijo = Fijo(
        "2. **No** acredita qué contenía el material antes de la intervención del\n\
        \x20  perito, ni quién lo creó, ni si fue alterado con anterioridad.\n\
         3. **No** contiene conclusión alguna sobre intrusiones, autoría o\n\
        \x20  responsabilidad. Eso corresponde al dictamen, no a la herramienta.\n",
    );

    /// Numeral 4. Exige [`FechaCierta`] —la MISMA condición que §6— porque remite
    /// expresamente a lo que §6 dice. Cuando cada uno tenía su condición, el
    /// numeral 4 se apoyaba en un §6 que, con el acta rota, decía otra cosa. Un
    /// sello VÁLIDO pero SIN ANCLAR lo produce igual un certificado que el
    /// adversario emitió hace un minuto. Cuarta revisión.
    pub const ALCANCE_4: Segun<FechaCierta> = Segun::nueva(
        "4. La fecha de adquisición es la del reloj de la máquina. Lo que una\n\
        \x20  autoridad independiente certifica (numeral 6) es que la firma ya\n\
        \x20  existía en ese instante — no que la adquisición ocurriera entonces.\n\n",
        "4. La fecha registrada es la del reloj de la máquina, contrastada según se\n\
        \x20  indica en el numeral 2. Sin sello de tiempo de tercero acreditado, prueba\n\
        \x20  orden relativo, no fecha cierta oponible.\n\n",
    );

    // -------------------------------------------------------- 9. fundamento
    pub const SEC_FUNDAMENTO: Fijo = Fijo(
        "## 9. Fundamento normativo\n\n\
         - **Ley 527 de 1999, arts. 8 a 11.** Un mensaje de datos es íntegro si ha\n\
        \x20 permanecido completo e inalterado; su fuerza probatoria se valora según\n\
        \x20 la confiabilidad de la forma en que se generó, archivó o comunicó, la\n\
        \x20 forma en que se conservó su integridad y la identificación de su\n\
        \x20 iniciador. Los tres extremos son, exactamente, lo que esta acta documenta.\n\
         - **CGP (Ley 1564 de 2012), art. 247.** Los mensajes de datos se valoran en\n\
        \x20 el formato en que fueron generados; de ahí que se sellen los archivos\n\
        \x20 originales y no una impresión.\n\
         - **CGP, art. 226.** El dictamen debe ser claro, preciso, exhaustivo y\n\
        \x20 detallado, y explicar los exámenes, métodos e investigaciones efectuados.\n\
        \x20 Esta acta es el soporte metodológico de esa exigencia.\n\
         - **CPP (Ley 906 de 2004), art. 254.** Factores de la cadena de custodia:\n\
        \x20 identidad, estado original, condiciones de recolección, preservación,\n\
        \x20 embalaje y envío; lugares y fechas de permanencia y los cambios que cada\n\
        \x20 custodio realizó.\n\n\
         Ver `MARCO_JURIDICO.md` para el detalle y las fuentes.\n\n",
    );

    // -------------------------------------------------------------- anexo
    pub const SEC_ANEXO: Fijo = Fijo(
        "## Anexo. Elementos\n\n\
         | # | Ruta | Tipo | Bytes | SHA-256 | Modificado (UTC) | Estado |\n\
         |---|---|---|---|---|---|---|\n",
    );
    pub const FILA_ELEMENTO: Fijo = Fijo("| {} | {} | {} | {} | {} | {} | {} |\n");

    /// Las cinco afirmaciones de [`Fecha`], para que un `match` exhaustivo elija.
    ///
    /// Es el sitio donde el compilador hace el trabajo: un estado nuevo en `Fecha`
    /// deja de compilar aquí hasta que se le escribe su texto. Antes esto eran tres
    /// `if` anidados dentro de un brazo de `match`, y a la afirmación más fuerte del
    /// documento se le arrancó el respaldo en tres rondas por tres caminos.
    pub(super) fn por_fecha(f: &Fecha) -> &'static PorFecha {
        match f {
            Fecha::Cierta => &FECHA_CIERTA,
            Fecha::FirmaSinAutoridad => &FECHA_SIN_AUTORIDAD,
            Fecha::SoloElCampoDeFirma => &FECHA_SOLO_EL_CAMPO,
            Fecha::NoSeSostiene => &FECHA_NO_SE_SOSTIENE,
            Fecha::Ausente => &FECHA_AUSENTE,
        }
    }
}

// ==========================================================================
// 6. El armado
// ==========================================================================

pub fn markdown(acta: &Acta, verificada: &ActaVerificada, sello: &SelloVerificado) -> String {
    let mut d = Documento::nuevo(Respaldo::nuevo(verificada, sello));

    cabecera(&mut d, acta);
    perito(&mut d, acta);
    adquisicion(&mut d, acta);
    resumen(&mut d, acta);
    raiz(&mut d, acta, verificada);
    firma(&mut d, acta);
    fecha_cierta(&mut d, acta, sello);
    d.fijo(&dicho::SEC_VERIFICAR);
    alcance(&mut d);
    d.fijo(&dicho::SEC_FUNDAMENTO);
    anexo(&mut d, acta);

    d.terminar()
}

fn cabecera(d: &mut Documento, acta: &Acta) {
    d.fijo(&dicho::TITULO);
    d.fijo_con(&dicho::REFERENCIA, &[&Dato::linea(&acta.caso.referencia)]);
    d.fijo_con(&dicho::DESCRIPCION, &[&Dato::bloque(&acta.caso.descripcion)]);
}

fn perito(d: &mut Documento, acta: &Acta) {
    d.fijo(&dicho::SEC_PERITO);
    d.fijo_con(&dicho::PERITO_NOMBRE, &[&Dato::linea(&acta.perito.nombre)]);
    d.fijo_con(&dicho::PERITO_ID, &[&Dato::linea(&acta.perito.identificacion)]);
    d.fijo(&dicho::PERITO_CLAVE);
    d.valla(&EnValla::huella_de(&acta.perito.clave_publica));
}

fn adquisicion(d: &mut Documento, acta: &Acta) {
    let a = &acta.adquisicion;
    d.fijo(&dicho::SEC_ADQUISICION);
    d.fijo_con(&dicho::ADQ_ORIGEN, &[&Dato::linea(&a.origen)]);
    d.fijo_con(&dicho::ADQ_METODO, &[&Dato::linea(&a.metodo)]);
    d.fijo_con(&dicho::ADQ_HERRAMIENTA, &[&Dato::linea(&a.herramienta)]);
    d.fijo_con(&dicho::ADQ_ALGORITMOS, &[&Dato::linea(&a.algoritmos)]);
    d.fijo(&dicho::ADQ_ACCESO);

    d.fijo(&dicho::SEC_RELOJ);
    d.fijo_con(&dicho::RELOJ_INICIO, &[&Dato::linea(&a.reloj.inicio_utc)]);
    d.fijo_con(&dicho::RELOJ_FIN, &[&Dato::linea(&a.reloj.fin_utc)]);
    d.fijo_con(&dicho::RELOJ_DESFASE, &[&Dato::linea(&a.reloj.desfase_local_utc)]);
    d.fijo_con(&dicho::RELOJ_CONTRASTE, &[&Dato::linea(&a.reloj.verificacion)]);
}

fn resumen(d: &mut Documento, acta: &Acta) {
    let ilegibles: Vec<&Elemento> =
        acta.elementos.iter().filter(|e| e.estado.starts_with("ERROR")).collect();
    let bytes: u64 = acta.elementos.iter().map(|e| e.bytes).sum();

    d.fijo(&dicho::SEC_RESUMEN);
    d.fijo(&dicho::TABLA_RESUMEN);
    d.fijo_con(
        &dicho::FILA_RESUMEN,
        &[
            &Dato::numero(acta.elementos.len() as u64),
            &Dato::numero(verificables(&acta.elementos) as u64),
            &Dato::numero(ilegibles.len() as u64),
            &Dato::numero(bytes),
        ],
    );

    if ilegibles.is_empty() {
        return;
    }
    d.fijo(&dicho::ILEGIBLES_AVISO);
    d.segun(&dicho::ILEGIBLES_QUE_CONSTA);
    for e in ilegibles {
        d.fijo_con(&dicho::ILEGIBLE_ITEM, &[&Dato::linea(&e.ruta), &Dato::linea(&e.estado)]);
    }
    d.salto();
}

fn raiz(d: &mut Documento, acta: &Acta, verificada: &ActaVerificada) {
    let motivo = match verificada {
        ActaVerificada::Invalida(m) => Dato::linea(m),
        ActaVerificada::Valida => Dato::linea(""),
    };
    d.fijo(&dicho::SEC_RAIZ);
    d.segun_con(&dicho::RAIZ, &[], &[&motivo]);

    // La raíz solo se imprime cuando el acta verifica: en el otro camino la frase
    // que le da sentido ya no está, y el número suelto invitaría a leerlo como si
    // significara algo. Dentro de la valla el escapado no vale nada, así que solo
    // entra si tiene la forma de un SHA-256.
    if !matches!(verificada, ActaVerificada::Valida) {
        return;
    }
    match EnValla::hex64(&acta.raiz_merkle) {
        Some(v) => d.valla(&v),
        None => d.fijo_con(&dicho::RAIZ_SIN_FORMA, &[&Dato::linea(&acta.raiz_merkle)]),
    }
}

fn firma(d: &mut Documento, acta: &Acta) {
    d.fijo(&dicho::SEC_FIRMA);
    let Some(f) = &acta.firma else {
        d.fijo(&dicho::FIRMA_AUSENTE);
        return;
    };
    d.fijo_con(&dicho::FIRMA_ALGORITMO, &[&Dato::linea(&f.algoritmo)]);
    d.segun(&dicho::FIRMA_COBERTURA);
    d.fijo(&dicho::FIRMA_HUELLA);
    d.valla(&EnValla::huella_de(&f.valor));
    d.fijo(&dicho::FIRMA_NOTA);
}

fn fecha_cierta(d: &mut Documento, acta: &Acta, sello: &SelloVerificado) {
    d.fijo(&dicho::SEC_FECHA);

    // El `match` exhaustivo: cada estado de `Fecha` tiene su texto, y añadir uno
    // nuevo no compila hasta que se escribe el suyo.
    let texto = dicho::por_fecha(&d.respaldo().fecha);
    let datos: Vec<Dato> = match (&d.respaldo().fecha, sello) {
        (Fecha::Cierta | Fecha::FirmaSinAutoridad, SelloVerificado::Valido(t, _)) => {
            vec![Dato::linea(&t.fecha_utc)]
        }
        (Fecha::NoSeSostiene, SelloVerificado::Invalido(m)) => vec![Dato::linea(m)],
        _ => vec![],
    };
    d.por_fecha(texto, &datos.iter().collect::<Vec<_>>());

    // El detalle del token y el bloque de alcance, solo cuando hay un token
    // correctamente firmado.
    //
    // El `SELLO_ALCANCE` sí afirma cosas de esta acta —«verificó que el sello
    // corresponde exactamente a la firma de esta acta»— y aun así es un `Fijo`. La
    // razón es que aquí la garantía la da el propio destructurado: `t` y `confianza`
    // NO EXISTEN fuera de la rama `Valido`, y sin ellos no hay bloque que escribir.
    // Es el mismo mecanismo que un `Segun` —una afirmación que necesita su prueba
    // para poder escribirse— solo que la prueba aquí es el dato mismo.
    let SelloVerificado::Valido(t, confianza) = sello else {
        return;
    };
    d.fijo_con(&dicho::SELLO_AUTORIDAD, &[&Dato::linea(confianza.autoridad())]);
    d.fijo_con(&dicho::SELLO_POLITICA, &[&Dato::linea(&t.politica)]);
    d.fijo_con(&dicho::SELLO_SERIE, &[&Dato::linea(&t.serie)]);
    d.fijo(&dicho::SELLO_PROTOCOLO);
    if let Some(st) = &acta.sello_tiempo {
        d.fijo(&dicho::SELLO_HUELLA);
        d.valla(&EnValla::huella_de(&st.token));
    }
    d.fijo(&dicho::SELLO_ALCANCE);
    d.segun(&dicho::SELLO_ACREDITACION);
    d.fijo(&dicho::SELLO_COMO);
}

fn alcance(d: &mut Documento) {
    d.fijo(&dicho::SEC_ALCANCE);
    d.segun(&dicho::ALCANCE_1);
    d.fijo(&dicho::ALCANCE_2_Y_3);
    d.segun(&dicho::ALCANCE_4);
}

fn anexo(d: &mut Documento, acta: &Acta) {
    d.fijo(&dicho::SEC_ANEXO);
    for (i, e) in acta.elementos.iter().enumerate() {
        d.fijo_con(
            &dicho::FILA_ELEMENTO,
            &[
                &Dato::numero(i as u64 + 1),
                &Dato::linea(&e.ruta),
                &Dato::linea(&e.tipo),
                &Dato::numero(e.bytes),
                &Dato::o_guion(&e.sha256),
                &Dato::o_guion(&e.modificado_utc),
                &Dato::linea(&e.estado),
            ],
        );
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::acta::{Adquisicion, Caso, Firma, Perito, Reloj};

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
            // Las llaves, que son lo que abriría un hueco de plantilla si el
            // relleno se hiciera al revés (recorriendo el resultado en vez de la
            // plantilla). Se comprueban aquí para que se note si dejan de escaparse.
            "{} y {}",
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
        let Dato(sangrado) = Dato::bloque("    texto sangrado");
        assert!(!sangrado.starts_with(' '));
        let Dato(hola) = Dato::bloque("  hola");
        assert_eq!(desescapar(&hola), "hola");
    }

    /// Un valor que no tiene forma de SHA-256 no puede entrar en una valla de
    /// código, donde el escapado no vale nada.
    #[test]
    fn la_valla_no_admite_un_valor_de_forma_no_comprobada() {
        assert!(EnValla::hex64(&"a".repeat(64)).is_some());
        assert!(EnValla::hex64("no es un hash").is_none());
        assert!(EnValla::hex64("```\ninyección\n```").is_none());
        // Ni uno de longitud correcta con un carácter no hexadecimal.
        assert!(EnValla::hex64(&format!("`{}", "a".repeat(63))).is_none());
    }

    /// El relleno recorre la PLANTILLA, así que un `{}` dentro de un dato no puede
    /// abrir un hueco nuevo — ni aunque el escapado no lo tocara.
    #[test]
    fn un_dato_no_puede_abrir_un_hueco_de_plantilla() {
        let mut d = Documento::nuevo(Respaldo {
            integra: true,
            anclada: false,
            fecha: Fecha::Ausente,
        });
        d.fijo_con(&Fijo("[{}]"), &[&Dato::linea("{} sobra")]);
        // El segundo `{}` viaja como texto del dato, escapado, y no consumió nada.
        let md = d.terminar();
        assert!(md.starts_with("[\\{\\} sobra]"), "{md}");
    }

    /// La afirmación positiva de un `Segun` no aparece cuando su condición falla, y
    /// la negativa no aparece cuando se cumple. Se casa contra las CONSTANTES: si
    /// alguien reflúa un párrafo, los dos lados se mueven a la vez.
    #[test]
    fn cada_afirmacion_sigue_a_su_condicion() {
        let mut a = acta_con_inyeccion_en_todo();
        a.caso = Caso { referencia: "R-1".into(), descripcion: "prueba".into() };
        a.raiz_merkle = "a".repeat(64);
        a.firma = Some(Firma { algoritmo: "Ed25519".into(), valor: String::new() });

        let rota = markdown(
            &a,
            &ActaVerificada::Invalida("la firma NO verifica".into()),
            &SelloVerificado::Ausente,
        );
        let sana = markdown(&a, &ActaVerificada::Valida, &SelloVerificado::Ausente);

        for (nombre, con, sin) in [
            ("RAIZ", dicho::RAIZ.con(), dicho::RAIZ.sin()),
            ("FIRMA_COBERTURA", dicho::FIRMA_COBERTURA.con(), dicho::FIRMA_COBERTURA.sin()),
            ("ALCANCE_1", dicho::ALCANCE_1.con(), dicho::ALCANCE_1.sin()),
        ] {
            assert!(dice(&sana, con), "[{nombre}] falta la afirmación en el acta sana");
            assert!(!dice(&sana, sin), "[{nombre}] sobra la negativa en el acta sana");
            assert!(dice(&rota, sin), "[{nombre}] falta la negativa en el acta rota");
            assert!(
                !dice(&rota, con),
                "[{nombre}] la afirmación sobrevivió al veredicto que la desmiente:\n{rota}"
            );
        }

        // Y la raíz no se imprime cuando el acta no verifica: sin la frase que le da
        // sentido, el número suelto invita a leerlo como si significara algo.
        assert!(sana.contains(&a.raiz_merkle), "la raíz comprobada sí se imprime:\n{sana}");
        assert!(!rota.contains(&a.raiz_merkle), "se imprimió la raíz de un acta rota:\n{rota}");
    }

    /// El numeral 4 del §8 y la §6 comparten condición, así que no se pueden
    /// desincronizar: sin sello no hay ninguna de las dos.
    #[test]
    fn el_numeral_cuatro_no_puede_remitir_a_una_seccion_que_dice_otra_cosa() {
        let mut a = acta_con_inyeccion_en_todo();
        a.caso = Caso { referencia: "R-1".into(), descripcion: "prueba".into() };
        let md = markdown(&a, &ActaVerificada::Valida, &SelloVerificado::Ausente);
        assert!(dice(&md, dicho::FECHA_AUSENTE.texto()), "{md}");
        assert!(
            dice(&md, dicho::ALCANCE_4.sin()),
            "sin sello, el numeral 4 no puede remitir a una certificación:\n{md}"
        );
        assert!(!dice(&md, dicho::ALCANCE_4.con()), "{md}");
    }
}

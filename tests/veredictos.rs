// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! El banco que faltaba: el ARTEFACTO y los CÓDIGOS DE SALIDA.
//!
//! # Por qué existe
//!
//! Cinco pasadas de `security-review` sobre la rama del sello encontraron 2, 2, 3,
//! 5 y 6 defectos — el ritmo SUBIENDO— y **quince de los dieciocho estaban en la
//! capa que reporta**: el documento que se anexa al dictamen, la salida por
//! pantalla y el código de salida de un comando.
//!
//! La causa se midió y es concreta: **ninguna de las 84 pruebas ejercía la salida
//! del CLI ni los códigos de salida**. Tres de los seis de la quinta ronda eran
//! invisibles en verde por eso, y el sitio de otro no lo renderizaba ninguna
//! prueba porque solo se ejercitaba una de las cuatro combinaciones de veredicto.
//!
//! Parchear una capa sin red produce exactamente lo que produjo: cada arreglo tapa
//! un caso y abre el de al lado. Dos de los seis defectos de la quinta ronda los
//! causaron los arreglos de la cuarta.
//!
//! # Qué fija, entonces
//!
//! 1. Que los tres comandos —`verificar`, `acta`, `custodia verificar`— devuelvan
//!    **el mismo veredicto** sobre el mismo archivo. Un comando más permisivo que
//!    otro es el que recomendaría quien entrega algo forjado.
//! 2. Que **ninguna afirmación** del documento sobreviva al veredicto que la
//!    desmiente, en las cuatro combinaciones.
//! 3. Que **nada de lo que viene del JSON** llegue a la pantalla sin sanear: un
//!    escape de terminal reescribía el veredicto que lee una persona.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::OnceLock;

use quipu::pqsign::{TripleSigningKey, generate_triple_keypair};
use base64::{Engine, engine::general_purpose::STANDARD};
use tunjo::acta::{Acta, Firma};
use tunjo::informe::{self, ActaVerificada, SelloVerificado, dice, dicho};
use tunjo::custodia::{self, Evento};
use tunjo::sellado::{self, Datos};

// ------------------------------------------------------------------ andamiaje

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tunjo")
}

/// Clave compartida: `generate_triple_keypair` tarda cerca de un minuto sin
/// optimizar —SLH-DSA no es barato— y generarla por prueba convertiría esta suite
/// en media hora de espera. Es el mismo criterio de `tests/integracion.rs`.
fn firmante() -> &'static TripleSigningKey {
    static CLAVE: OnceLock<TripleSigningKey> = OnceLock::new();
    CLAVE.get_or_init(|| generate_triple_keypair().1)
}

fn datos() -> Datos {
    Datos {
        referencia: "RAD-2026-001".into(),
        descripcion: "Sellado de prueba".into(),
        perito: "Perito de prueba".into(),
        identificacion: "CC 000".into(),
        metodo: "copia lógica en solo lectura".into(),
        reloj: Some("contrastado con reloj patrón".into()),
        admitir_ilegibles: false,
        autoridad_sello: None,
    }
}

/// Un acta REAL, firmada de verdad sobre material de verdad.
fn acta_firmada(dir: &Path) -> Acta {
    fs::write(dir.join("evidencia.txt"), b"material probatorio\n").unwrap();
    sellado::sellar(dir, firmante(), &datos()).unwrap()
}

/// Vuelve a fijar la raíz y a firmar tras haber alterado campos.
///
/// `sellado` no expone esto y no debe: firmar un acta que otro construyó no es una
/// operación del producto. En la prueba sí hace falta, porque **cualquiera que
/// entregue un acta la firma con SU clave**, y por eso el camino de éxito es
/// alcanzable con contenido elegido por el atacante — que es justo lo que hay que
/// probar.
fn refirmar(mut acta: Acta, sk: &TripleSigningKey) -> Acta {
    acta.firma = None;
    acta.fijar_raiz().expect("la raíz se recalcula");
    let firma = sk.sign(&acta.bytes_canonicos());
    acta.firma = Some(Firma {
        algoritmo: "Ed25519+ML-DSA-87+SLH-DSA".to_string(),
        valor: STANDARD.encode(&firma),
    });
    acta
}

/// El token REAL de DigiCert que ya vive en `fijos/`, y lo que acredita.
///
/// Con él se construye un `SelloVerificado::Valido` de verdad, en sus dos grados de
/// confianza. Hasta la sexta revisión `Valido` no aparecía en NINGUNA prueba
/// —requiere un `DatosSello` y una `Confianza` que solo salen de un token real— y
/// por eso unas setenta líneas de la sección 6 no las ejecutaba nada: los tres
/// subcasos, la autoridad, la política, la serie, la huella del token y el bloque
/// «Alcance de esta comprobación». Es la sección con el peor historial del archivo:
/// ahí vivieron los defectos de las rondas primera, segunda y cuarta.
fn sello_real(anclado: bool) -> SelloVerificado {
    const TOKEN: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fijos/sello_digicert.tsr"));
    const HASH: [u8; 32] = [
        0xdd, 0xd5, 0x04, 0x70, 0x1c, 0x62, 0x4c, 0x96, 0x58, 0x26, 0xc7, 0x38, 0x75, 0xb6, 0x1e,
        0x8d, 0x70, 0x07, 0x3d, 0x58, 0xf1, 0x7b, 0xc2, 0xe2, 0xd2, 0xc4, 0x15, 0x94, 0x59, 0x64,
        0xf3, 0xc8,
    ];
    let datos = tunjo::sello_tiempo::verificar(TOKEN, &HASH).expect("el token de fijos es válido");

    // El ancla se saca del propio token: aquí interesa obtener una `Confianza`
    // ANCLADA de verdad para que el documento recorra esa rama, no probar la
    // confianza —eso lo hace `tests/firma_cms.rs`.
    let anclas: Vec<x509_cert::Certificate> = if anclado {
        use cms::cert::CertificateChoices;
        use der::Decode;
        let ci = cms::content_info::ContentInfo::from_der(TOKEN).unwrap();
        let sd: cms::signed_data::SignedData = ci.content.decode_as().unwrap();
        sd.certificates
            .unwrap()
            .0
            .iter()
            .filter_map(|c| match c {
                CertificateChoices::Certificate(c) => Some(c.clone()),
                _ => None,
            })
            .filter(|c| c.tbs_certificate.subject.to_string().contains("Trusted Root G4"))
            .collect()
    } else {
        Vec::new()
    };
    let confianza = tunjo::firma_cms::verificar_firma(TOKEN, &datos.fecha_utc, &anclas)
        .expect("el token de fijos tiene firma válida");
    assert_eq!(
        confianza.acredita_autoridad(),
        anclado,
        "el ayudante debe producir el grado de confianza que promete, o la prueba \
         que lo use no probaría lo que dice"
    );
    SelloVerificado::Valido(datos, confianza)
}

/// Las SEIS combinaciones de veredicto que el documento tiene que distinguir.
fn combinaciones() -> Vec<(&'static str, ActaVerificada, SelloVerificado)> {
    vec![
        ("acta invalida", ActaVerificada::Invalida("no verifica".into()), SelloVerificado::Ausente),
        ("acta valida, sin sello", ActaVerificada::Valida, SelloVerificado::Ausente),
        (
            "acta valida, sello invalido",
            ActaVerificada::Valida,
            SelloVerificado::Invalido("el token no lleva firmante".into()),
        ),
        (
            "acta invalida, sello invalido",
            ActaVerificada::Invalida("no verifica".into()),
            SelloVerificado::Invalido("el token no lleva firmante".into()),
        ),
        // Las dos que faltaban, y son las que más historial tienen.
        ("acta valida, sello valido SIN anclar", ActaVerificada::Valida, sello_real(false)),
        ("acta valida, sello valido ANCLADO", ActaVerificada::Valida, sello_real(true)),
    ]
}

fn escribir(ruta: &Path, acta: &Acta) {
    fs::write(ruta, serde_json::to_vec_pretty(acta).unwrap()).unwrap();
}

fn correr(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("el binario debe ejecutarse")
}

fn codigo(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}


/// Una cadena de custodia REAL sobre el acta dada, firmada con la misma clave.
///
/// Hace falta porque `custodia verificar --acta` era, hasta la sexta revisión, el
/// comando que NINGUNA prueba del repositorio ejercía —y es donde vivieron las dos
/// asimetrías de código de salida que la cuarta y la quinta encontraron—.
fn cadena_sobre(acta: &Acta, dir: &Path) -> std::path::PathBuf {
    let adquisicion = Evento {
        tipo: "adquisicion".into(),
        actor: "Perito de prueba".into(),
        identificacion: "CC 000".into(),
        rol: "perito".into(),
        fecha_utc: "2026-07-30T08:00:00Z".into(),
        reloj: "NO VERIFICADO".into(),
        descripcion: "recogida del material".into(),
    };
    let cadena = custodia::iniciar(&acta.bytes_canonicos(), adquisicion, firmante());
    let ruta = dir.join("cadena.json");
    fs::write(&ruta, serde_json::to_vec_pretty(&cadena).unwrap()).unwrap();
    ruta
}

// ----------------------------------------------- 1. los comandos deben coincidir

/// Un acta cuya firma NO verifica tiene que fallar en TODOS los comandos.
///
/// La cuarta y la quinta revisión encontraron dos asimetrías de esta clase: un
/// acta con `firma: null` daba exit 0 en `custodia verificar --acta` y exit 1 en
/// `tunjo verificar`, y un sello de tiempo forjado daba 0 en uno y 1 en los otros.
/// El comando permisivo es precisamente el que recomendaría quien entrega el
/// archivo.
#[test]
fn los_comandos_no_se_contradicen_sobre_un_acta_que_no_verifica() {
    let dir = tempfile::tempdir().unwrap();
    let mut acta = acta_firmada(dir.path());

    // Se altera el contenido DESPUÉS de firmar: la raíz declarada deja de
    // corresponder a los elementos y la firma no cuadra.
    acta.elementos[0].sha256 = "0".repeat(64);
    let ruta = dir.path().join("acta.json");
    escribir(&ruta, &acta);
    let r = ruta.to_str().unwrap();

    // La cadena se construye sobre el acta YA alterada, así que su ancla cuadra y
    // la cadena verifica ÍNTEGRA: es exactamente el caso en que el comando podría
    // dar verde por la mitad que sí cuadra.
    let cadena = cadena_sobre(&acta, dir.path());
    let c = cadena.to_str().unwrap();

    let v = correr(&["verificar", r]);
    let a = correr(&["acta", r]);
    let cv = correr(&["custodia", "verificar", "--cadena", c, "--acta", r]);

    assert_eq!(codigo(&v), 1, "`verificar` debe fallar:\n{}", texto(&v));
    assert_eq!(
        codigo(&a),
        1,
        "`acta` NO puede ser más permisivo que `verificar` sobre el mismo archivo:\n{}",
        texto(&a)
    );
    assert_eq!(
        codigo(&cv),
        1,
        "`custodia verificar --acta` NO puede ser más permisivo que los otros dos — es \
         donde vivieron las dos asimetrías de la cuarta y la quinta ronda:\n{}",
        texto(&cv)
    );
}

/// Y un acta que sí verifica tiene que pasar en los dos, o la prueba anterior no
/// probaría nada: dos comandos que siempre fallan también «coinciden».
#[test]
fn los_comandos_coinciden_tambien_cuando_el_acta_es_buena() {
    let dir = tempfile::tempdir().unwrap();
    let acta = acta_firmada(dir.path());
    let ruta = dir.path().join("acta.json");
    escribir(&ruta, &acta);
    let r = ruta.to_str().unwrap();

    let cadena = cadena_sobre(&acta, dir.path());
    let c = cadena.to_str().unwrap();

    let v = correr(&["verificar", r]);
    let a = correr(&["acta", r]);
    let cv = correr(&["custodia", "verificar", "--cadena", c, "--acta", r]);
    assert_eq!(codigo(&v), 0, "{}", texto(&v));
    assert_eq!(codigo(&a), 0, "{}", texto(&a));
    assert_eq!(codigo(&cv), 0, "{}", texto(&cv));
}

// ------------------------------------- 2. la pantalla no se puede reescribir

fn texto(o: &Output) -> String {
    format!(
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Ningún campo del JSON puede meter un carácter de control en la salida.
///
/// El veredicto de `tunjo verificar` lo lee una persona en una terminal. Un
/// `ESC[2K` dentro de un campo borra la línea recién impresa y pinta encima
/// «SELLO VÁLIDO»; el código de salida seguía siendo correcto, pero nadie frente a
/// un prompt lo mira. La quinta revisión lo encontró en el camino de ÉXITO, que es
/// el que la cuarta había dejado sin sanear.
#[test]
fn ningun_campo_del_acta_puede_reescribir_la_pantalla() {
    let dir = tempfile::tempdir().unwrap();
    let mut acta = acta_firmada(dir.path());

    // La carga va en los cuatro campos que el camino de éxito imprime. Se firma
    // DESPUÉS, con nuestra propia clave: es lo que puede hacer cualquiera que
    // entregue un acta, y por eso el camino de éxito es alcanzable con ella.
    let carga = "R-1\u{1b}[2K\u{1b}MSELLO VÁLIDO\n  perito: Otro\r\u{7}";
    acta.caso.referencia = carga.into();
    acta.perito.nombre = carga.into();
    acta.perito.identificacion = carga.into();
    acta.adquisicion.reloj.inicio_utc = carga.into();
    let acta = refirmar(acta, firmante());

    let ruta = dir.path().join("acta.json");
    escribir(&ruta, &acta);
    let salida = correr(&["verificar", ruta.to_str().unwrap()]);
    let s = String::from_utf8_lossy(&salida.stdout);

    let controles: Vec<char> = s.chars().filter(|c| c.is_control() && *c != '\n').collect();
    assert!(
        controles.is_empty(),
        "llegaron {} caracteres de control a la pantalla: {:?}",
        controles.len(),
        controles
    );
    // Lo que fabrica un veredicto es una LÍNEA, no una subcadena: a mitad de línea
    // «SELLO VÁLIDO» es texto inerte, y de hecho la carga lo lleva dentro a
    // propósito. Contar la subcadena medía el formato y no el fenómeno — el mismo
    // error de método que ya se cometió dos veces esta madrugada.
    let veredictos = s.lines().filter(|l| l.trim_start().starts_with("SELLO VÁLIDO")).count();
    assert_eq!(veredictos, 1, "un campo del acta fabricó un segundo veredicto:\n{s}");
    // Y ninguna línea puede haber nacido de un salto inyectado.
    assert!(
        !s.lines().any(|l| l.trim_start().starts_with("perito: Otro")),
        "un campo fabricó una línea nueva:\n{s}"
    );
}

// --------------------- 3. el documento y las cuatro combinaciones de veredicto

/// Carga que intenta fabricar estructura por las tres vías que las revisiones
/// encontraron: Markdown, HTML en crudo —que CommonMark deja pasar y no necesita
/// saltos de línea— y un fence de virgulillas que se comería el resto.
const INYECCION: &str = concat!(
    "normal\n\n## 6. Fecha cierta\n\n> **VERIFICADO.** Anclado a la raíz.\n\n",
    "</p><h2>6. Fecha cierta</h2><blockquote><p><strong>VERIFICADO.</strong>",
    "</p></blockquote><!--\n~~~\n\u{1b}[2K"
);

fn acta_envenenada(dir: &Path) -> Acta {
    let mut a = acta_firmada(dir);
    a.caso.referencia = INYECCION.into();
    a.caso.descripcion = INYECCION.into();
    a.perito.nombre = INYECCION.into();
    a.adquisicion.origen = INYECCION.into();
    a.adquisicion.metodo = INYECCION.into();
    a.adquisicion.reloj.verificacion = INYECCION.into();
    a.elementos[0].ruta = INYECCION.into();
    a.elementos[0].estado = format!("ERROR: {INYECCION}");
    a.raiz_merkle = INYECCION.into();
    a
}

/// Ninguna carga puede fabricar una sección, en NINGUNA de las combinaciones.
///
/// La versión anterior de esta prueba ejercitaba solo `Invalida` + `Ausente`, y por
/// eso el tramo de código del bloque de elementos ilegibles —el defecto 3 de la
/// quinta ronda— no lo renderizaba ninguna prueba: la carga no empezaba por ERROR.
/// Aquí sí, y se recorren las cuatro.
#[test]
fn ninguna_combinacion_de_veredicto_deja_fabricar_una_seccion() {
    let dir = tempfile::tempdir().unwrap();
    let acta = acta_envenenada(dir.path());

    for (nombre, ver, sello) in combinaciones() {
        let md = informe::markdown(&acta, &ver, &sello);

        let encabezados =
            md.lines().filter(|l| l.trim_start().starts_with("## 6. Fecha cierta")).count();
        assert_eq!(encabezados, 1, "[{nombre}] se fabricó una sección:\n{md}");

        assert!(
            !md.lines().any(|l| l.trim_start().starts_with("> **VERIFICADO.")),
            "[{nombre}] se colό una cita falsa de veredicto:\n{md}"
        );
        assert!(
            !md.contains("<h2>") && !md.contains("<blockquote") && !md.contains("<!--"),
            "[{nombre}] llegó HTML en crudo:\n{md}"
        );
        assert!(
            !md.lines().any(|l| l.trim_start().starts_with("~~~")),
            "[{nombre}] un fence inyectado abrió un bloque:\n{md}"
        );
        assert!(
            !md.chars().any(|c| c.is_control() && c != '\n'),
            "[{nombre}] sobrevivió un carácter de control"
        );
    }
}

/// Y la matriz de afirmaciones: cada veredicto suprime exactamente lo que debe.
///
/// Es la prueba que faltaba en las cinco rondas. Sin ella, cada arreglo tapaba una
/// afirmación y dejaba otra en pie —§4 y §5 mientras §6 ya estaba gateada, el
/// numeral 1 mientras el 4 sí, el bloque de éxito mientras los de error sí— y
/// nadie lo veía porque nada renderizaba las cuatro combinaciones.
#[test]
fn ninguna_afirmacion_sobrevive_al_veredicto_que_la_desmiente() {
    let dir = tempfile::tempdir().unwrap();
    let acta = acta_firmada(dir.path());

    // (a) Acta que NO verifica: no se afirma integridad ni cobertura, en ninguna
    //     sección y con cualquier estado de sello.
    for (nombre, sello) in [
        ("invalida+ausente", SelloVerificado::Ausente),
        ("invalida+sello_malo", SelloVerificado::Invalido("no vale".into())),
    ] {
        let md = informe::markdown(
            &acta,
            &ActaVerificada::Invalida("la firma NO verifica".into()),
            &sello,
        );
        // Se casa contra las CONSTANTES de `informe::dicho`, no contra copias del
        // texto: una copia deja de comprobar nada en cuanto alguien reflúa el
        // párrafo, y eso ya pasó en esta rama. Noveno hallazgo de la sexta ronda.
        assert!(dice(&md, dicho::RAIZ.sin()), "[{nombre}] falta el aviso:\n{md}");
        assert!(
            !dice(&md, dicho::RAIZ.con()),
            "[{nombre}] afirma integridad de un acta que no verifica"
        );
        assert!(
            !dice(&md, dicho::FIRMA_COBERTURA.con()),
            "[{nombre}] afirma cobertura de una firma que no verifica"
        );
        // §8 numeral 1: el defecto 2 de la quinta ronda.
        assert!(
            !dice(&md, dicho::ALCANCE_1.con()),
            "[{nombre}] el numeral 1 sigue acreditando el contenido:\n{md}"
        );
    }

    // (b) Acta válida SIN sello: no se habla de fecha cierta.
    let md = informe::markdown(&acta, &ActaVerificada::Valida, &SelloVerificado::Ausente);
    assert!(dice(&md, dicho::FECHA_AUSENTE.texto()), "{md}");
    assert!(
        !dice(&md, dicho::FECHA_CIERTA.texto()),
        "sin sello no se puede certificar nada:\n{md}"
    );
    // Y sí se afirma lo que corresponde, o la prueba no discrimina.
    assert!(dice(&md, dicho::FIRMA_COBERTURA.con()), "un acta válida sí afirma cobertura:\n{md}");
}

/// «Certificó» y «fecha cierta» aparecen SOLO con la autoridad acreditada.
///
/// Es la afirmación más fuerte del documento y la que tres rondas distintas
/// consiguieron arrancarle sin derecho: la primera con un token sin firmante, la
/// segunda leyéndola del JSON, y la cuarta con un sello válido pero SIN ANCLAR
/// —que es lo que produce igual un autofirmado emitido hace un minuto—.
#[test]
fn la_fecha_cierta_se_afirma_solo_con_la_autoridad_acreditada() {
    let dir = tempfile::tempdir().unwrap();
    let acta = acta_firmada(dir.path());

    let sin_anclar = informe::markdown(&acta, &ActaVerificada::Valida, &sello_real(false));
    assert!(
        !dice(&sin_anclar, dicho::FECHA_CIERTA.texto()),
        "un sello sin anclar no puede certificar nada:\n{sin_anclar}"
    );
    assert!(
        dice(&sin_anclar, dicho::FECHA_SIN_AUTORIDAD.texto()),
        "y tiene que decir que la identidad no está acreditada:\n{sin_anclar}"
    );
    assert!(
        dice(&sin_anclar, dicho::SELLO_ACREDITACION.sin()),
        "el alcance tiene que decir que no comprobó a quién pertenece:\n{sin_anclar}"
    );

    let anclado = informe::markdown(&acta, &ActaVerificada::Valida, &sello_real(true));
    assert!(
        dice(&anclado, dicho::FECHA_CIERTA.texto()),
        "con la autoridad acreditada SÍ se afirma, o esta prueba no discriminaría:\n{anclado}"
    );
    assert!(dice(&anclado, dicho::SELLO_ACREDITACION.con()), "{anclado}");

    // Y con el acta inválida, ni siquiera anclado: el sello cubre el valor del
    // campo de firma, no el cuerpo del acta.
    let acta_mala = informe::markdown(
        &acta,
        &ActaVerificada::Invalida("no verifica".into()),
        &sello_real(true),
    );
    assert!(
        !dice(&acta_mala, dicho::FECHA_CIERTA.texto()),
        "si la firma del acta no verifica, «la firma de esta acta» no significa nada:\n{acta_mala}"
    );
    assert!(
        dice(&acta_mala, dicho::FECHA_SOLO_EL_CAMPO.texto()),
        "y tiene que decir qué es lo único que el sello sí dice:\n{acta_mala}"
    );
}

/// Lo que el documento dice del TOKEN no depende de la firma del ACTA.
///
/// Son dos comprobaciones distintas y el bloque «Alcance de esta comprobación»
/// describe la primera. Cuando el alcance colgaba de la condición del acta, un acta
/// rota con un sello impecablemente anclado salía diciendo que no se había
/// comprobado a quién pertenece el certificado — y eso es falso: sí se comprobó.
/// Es la misma clase de defecto que las seis rondas, en la dirección contraria: una
/// negación sin respaldo también es una afirmación sin respaldo.
#[test]
fn el_alcance_del_token_no_depende_de_la_firma_del_acta() {
    let dir = tempfile::tempdir().unwrap();
    let acta = acta_firmada(dir.path());

    for (nombre, ver) in [
        ("acta íntegra", ActaVerificada::Valida),
        ("acta rota", ActaVerificada::Invalida("no verifica".into())),
    ] {
        let md = informe::markdown(&acta, &ver, &sello_real(true));
        assert!(
            dice(&md, dicho::SELLO_ACREDITACION.con()),
            "[{nombre}] el ancla SÍ se comprobó, lo diga lo que diga la firma del acta:\n{md}"
        );
        assert!(!dice(&md, dicho::SELLO_ACREDITACION.sin()), "[{nombre}]:\n{md}");
    }

    // Y sin ancla, la negativa — o la prueba no discriminaría.
    let md = informe::markdown(&acta, &ActaVerificada::Valida, &sello_real(false));
    assert!(dice(&md, dicho::SELLO_ACREDITACION.sin()), "{md}");
}

/// El numeral 4 del §8 no puede remitir a una §6 que dice otra cosa.
///
/// Las dos dependen de la MISMA condición —`FechaCierta`: autoridad acreditada Y
/// acta íntegra— desde el rediseño. Antes el numeral 4 solo exigía la autoridad
/// acreditada, así que con el acta rota afirmaba «lo que una autoridad
/// independiente certifica (numeral 6)» mientras el numeral 6 decía expresamente
/// que no certificaba nada del acta. Una condición compartida no se desincroniza.
#[test]
fn el_numeral_cuatro_y_la_seccion_seis_no_se_pueden_contradecir() {
    let dir = tempfile::tempdir().unwrap();
    let acta = acta_firmada(dir.path());

    for (nombre, ver, sello, remite) in [
        ("anclado + acta íntegra", ActaVerificada::Valida, sello_real(true), true),
        ("anclado + acta rota", ActaVerificada::Invalida("no".into()), sello_real(true), false),
        ("sin anclar", ActaVerificada::Valida, sello_real(false), false),
        ("sin sello", ActaVerificada::Valida, SelloVerificado::Ausente, false),
    ] {
        let md = informe::markdown(&acta, &ver, &sello);
        assert_eq!(
            dice(&md, dicho::ALCANCE_4.con()),
            remite,
            "[{nombre}] el numeral 4 remite a una certificación que la §6 no hace:\n{md}"
        );
        // Y si remite, la §6 tiene que estar diciéndolo de verdad.
        if remite {
            assert!(dice(&md, dicho::FECHA_CIERTA.texto()), "[{nombre}]:\n{md}");
        }
    }
}

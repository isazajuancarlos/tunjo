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
use tunjo::informe::{self, ActaVerificada, SelloVerificado};
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

/// Las cuatro combinaciones de veredicto que el documento tiene que distinguir.
fn combinaciones() -> Vec<(&'static str, ActaVerificada, SelloVerificado)> {
    vec![
        ("acta invalida", ActaVerificada::Invalida("no verifica".into()), SelloVerificado::Ausente),
        (
            "acta valida, sin sello",
            ActaVerificada::Valida,
            SelloVerificado::Ausente,
        ),
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

    let v = correr(&["verificar", r]);
    let a = correr(&["acta", r]);

    assert_eq!(codigo(&v), 1, "`verificar` debe fallar:\n{}", texto(&v));
    assert_eq!(
        codigo(&a),
        1,
        "`acta` NO puede ser más permisivo que `verificar` sobre el mismo archivo:\n{}",
        texto(&a)
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

    let v = correr(&["verificar", r]);
    let a = correr(&["acta", r]);
    assert_eq!(codigo(&v), 0, "{}", texto(&v));
    assert_eq!(codigo(&a), 0, "{}", texto(&a));
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
        assert!(md.contains("ESTA ACTA NO VERIFICA"), "[{nombre}] falta el aviso:\n{md}");
        assert!(
            !md.contains("produce una\nraíz distinta"),
            "[{nombre}] afirma integridad de un acta que no verifica"
        );
        assert!(
            !md.contains("**Comprobada.**"),
            "[{nombre}] afirma cobertura de una firma que no verifica"
        );
        // §8 numeral 1: el defecto 2 de la quinta ronda.
        assert!(
            !md.contains("Acredita que los elementos listados tenían exactamente"),
            "[{nombre}] el numeral 1 sigue acreditando el contenido:\n{md}"
        );
    }

    // (b) Acta válida SIN sello: no se habla de fecha cierta.
    let md = informe::markdown(&acta, &ActaVerificada::Valida, &SelloVerificado::Ausente);
    assert!(md.contains("NO lleva sello de tiempo"), "{md}");
    assert!(
        !md.contains("autoridad de sellado independiente certificó"),
        "sin sello no se puede certificar nada:\n{md}"
    );
    // Y sí se afirma lo que corresponde, o la prueba no discrimina.
    assert!(md.contains("**Comprobada.**"), "un acta válida sí afirma cobertura:\n{md}");
}

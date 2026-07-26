// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pruebas de punta a punta sobre el mismo camino que usa el CLI.
//!
//! Lo que se busca aquí no es que «pase»: es que **discrimine**. Un verificador
//! que dijera siempre «íntegro» pasaría cualquier prueba de camino feliz, así
//! que cada prueba de detección lleva su contraparte: se altera UNA cosa y se
//! comprueba que se señala esa y **solo** esa.

use std::fs;
use std::path::Path;

use quipu::pqsign::{TripleSigningKey, generate_triple_keypair};
use tunjo::acta::{Acta, ErrorActa};
use tunjo::recoleccion::{self, Discrepancia};
use tunjo::sellado::{self, Datos};

fn datos() -> Datos {
    Datos {
        referencia: "RAD-2026-001".into(),
        descripcion: "Sellado de prueba".into(),
        perito: "Juan Carlos Isaza Arenas".into(),
        identificacion: "CC 000".into(),
        metodo: "copia lógica en solo lectura".into(),
        reloj: Some("contrastado con reloj patrón".into()),
        admitir_ilegibles: false,
    }
}

fn material(dir: &Path, n: usize) {
    fs::create_dir_all(dir.join("sub")).unwrap();
    for i in 0..n {
        let destino = if i % 3 == 0 { dir.join("sub") } else { dir.to_path_buf() };
        fs::write(destino.join(format!("archivo{i:04}.txt")), format!("contenido {i}\n")).unwrap();
    }
}

fn firmante() -> TripleSigningKey {
    generate_triple_keypair().1
}

#[test]
fn sellar_y_verificar_un_directorio() {
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 10);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();

    assert!(acta.verificar_sello().is_ok());
    assert!(recoleccion::contrastar(&acta.elementos, dir.path()).unwrap().is_empty());
    // 10 archivos + el directorio `sub`.
    assert_eq!(acta.elementos.len(), 11);
}

#[test]
fn sellar_un_archivo_suelto() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("correo.eml");
    fs::write(&f, b"From: alguien\n").unwrap();
    let acta = sellado::sellar(&f, &firmante(), &datos()).unwrap();
    assert_eq!(acta.elementos.len(), 1);
    assert_eq!(acta.elementos[0].ruta, "correo.eml");
    assert!(acta.verificar_sello().is_ok());
}

#[test]
fn un_directorio_vacio_no_se_sella() {
    let dir = tempfile::tempdir().unwrap();
    let e = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap_err();
    assert!(e.to_string().contains("no hay nada que sellar"), "{e}");
}

#[test]
fn detecta_alteracion_de_contenido() {
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 5);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();

    fs::write(dir.path().join("archivo0001.txt"), "contenido alterado\n").unwrap();
    let d = recoleccion::contrastar(&acta.elementos, dir.path()).unwrap();
    assert_eq!(d.len(), 1, "debía señalar exactamente un elemento: {d:?}");
    match &d[0] {
        Discrepancia::Alterado { ruta, .. } => assert_eq!(ruta, "archivo0001.txt"),
        otro => panic!("discrepancia equivocada: {otro:?}"),
    }
}

#[test]
fn detecta_borrado_y_adicion() {
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 4);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();

    fs::remove_file(dir.path().join("archivo0001.txt")).unwrap();
    fs::write(dir.path().join("nuevo.txt"), "aparecido").unwrap();

    let d = recoleccion::contrastar(&acta.elementos, dir.path()).unwrap();
    assert_eq!(d.len(), 2, "{d:?}");
    assert!(d.contains(&Discrepancia::Ausente { ruta: "archivo0001.txt".into() }));
    assert!(d.contains(&Discrepancia::NoEstabaEnElActa { ruta: "nuevo.txt".into() }));
}

#[test]
fn mover_un_archivo_de_sitio_rompe_el_sello_del_conjunto() {
    // La cadena de custodia exige acreditar el ESTADO, no solo los bytes: el
    // mismo contenido en otra ruta es otro estado.
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 4);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();

    fs::rename(dir.path().join("archivo0001.txt"), dir.path().join("sub/archivo0001.txt")).unwrap();
    let d = recoleccion::contrastar(&acta.elementos, dir.path()).unwrap();
    assert_eq!(d.len(), 2, "{d:?}");
}

#[test]
fn el_contenido_intacto_no_produce_falsos_positivos() {
    // El reverso de las pruebas de detección: si señalara siempre, no serviría.
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 30);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();
    for _ in 0..10 {
        assert!(recoleccion::contrastar(&acta.elementos, dir.path()).unwrap().is_empty());
    }
}

#[test]
fn manipular_el_acta_invalida_el_sello() {
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 3);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();

    // 1. Cambiar el hash de un elemento: la raíz deja de corresponder.
    let mut a = acta.clone();
    a.elementos[0].sha256 = "00".repeat(32);
    assert!(matches!(a.verificar_sello(), Err(ErrorActa::RaizNoCoincide { .. })));

    // 2. Cambiar un dato del caso: la raíz sigue bien, la firma no.
    let mut b = acta.clone();
    b.caso.referencia = "OTRO-RADICADO".into();
    assert_eq!(b.verificar_sello(), Err(ErrorActa::FirmaInvalida));

    // 3. Cambiar el nombre del perito.
    let mut c = acta.clone();
    c.perito.nombre = "Otro".into();
    assert_eq!(c.verificar_sello(), Err(ErrorActa::FirmaInvalida));

    // 4. Quitar la firma.
    let mut d = acta.clone();
    d.firma = None;
    assert_eq!(d.verificar_sello(), Err(ErrorActa::SinFirma));
}

#[test]
fn la_firma_de_otra_clave_no_sirve() {
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 3);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();

    // Sustituir la clave pública por otra: la firma deja de validar. Es el
    // ataque de sustitución de clave, y debe fallar aunque el resto cuadre.
    use base64::{Engine, engine::general_purpose::STANDARD};
    let (otra_vk, _) = generate_triple_keypair();
    let mut a = acta.clone();
    a.perito.clave_publica = STANDARD.encode(otra_vk.to_bytes());
    assert_eq!(a.verificar_sello(), Err(ErrorActa::FirmaInvalida));
}

#[test]
fn el_acta_sobrevive_a_ir_y_volver_de_json() {
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 6);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();

    let json = serde_json::to_string_pretty(&acta).unwrap();
    let leida: Acta = serde_json::from_str(&json).unwrap();
    assert_eq!(acta, leida);
    assert!(leida.verificar_sello().is_ok(), "el acta debe verificarse tras leerse del disco");
}

#[test]
fn el_reloj_sin_verificar_queda_escrito_como_tal() {
    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 2);
    let mut d = datos();
    d.reloj = None;
    let acta = sellado::sellar(dir.path(), &firmante(), &d).unwrap();
    assert!(
        acta.adquisicion.reloj.verificacion.contains("NO VERIFICADO"),
        "la ausencia del dato debe constar, no rellenarse: {}",
        acta.adquisicion.reloj.verificacion
    );
}

#[cfg(unix)]
#[test]
fn un_archivo_ilegible_detiene_el_sellado() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    material(dir.path(), 3);
    let secreto = dir.path().join("ilegible.bin");
    fs::write(&secreto, b"algo").unwrap();
    fs::set_permissions(&secreto, fs::Permissions::from_mode(0o000)).unwrap();

    // Bajo root los permisos no impiden leer y la inyección de fallo no ocurre.
    if fs::File::open(&secreto).is_ok() {
        eprintln!("(omitida: se está ejecutando como root)");
        return;
    }

    let e = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap_err();
    assert!(e.to_string().contains("no se pudieron leer"), "{e}");

    // Con la bandera explícita sí sella, y el elemento consta como ERROR.
    let mut d = datos();
    d.admitir_ilegibles = true;
    let acta = sellado::sellar(dir.path(), &firmante(), &d).unwrap();
    let el = acta.elementos.iter().find(|e| e.ruta == "ilegible.bin").unwrap();
    assert!(el.estado.starts_with("ERROR"), "estado: {}", el.estado);
    assert!(el.sha256.is_empty(), "no puede haber hash de lo que no se leyó");
    assert!(acta.verificar_sello().is_ok());

    // Y no se afirma integridad sobre él: se dice que no es verificable.
    fs::set_permissions(&secreto, fs::Permissions::from_mode(0o644)).unwrap();
    let disc = recoleccion::contrastar(&acta.elementos, dir.path()).unwrap();
    assert!(
        disc.iter().any(|x| matches!(x, Discrepancia::NoVerificable { ruta, .. } if ruta == "ilegible.bin")),
        "{disc:?}"
    );
}

#[cfg(unix)]
#[test]
fn los_enlaces_simbolicos_no_se_siguen() {
    // Seguir un enlace sacaría al perito del material que le entregaron.
    let dir = tempfile::tempdir().unwrap();
    let fuera = tempfile::tempdir().unwrap();
    fs::write(fuera.path().join("ajeno.txt"), "material de otro").unwrap();
    material(dir.path(), 2);
    std::os::unix::fs::symlink(fuera.path(), dir.path().join("enlace")).unwrap();

    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();
    let enlace = acta.elementos.iter().find(|e| e.ruta == "enlace").unwrap();
    assert_eq!(enlace.tipo, "enlace");
    assert!(enlace.estado.starts_with("enlace ->"));
    assert!(
        !acta.elementos.iter().any(|e| e.ruta.contains("ajeno.txt")),
        "se siguió el enlace y se sellró material ajeno"
    );
}

/// Directiva de las 100+ operaciones: no basta con que funcione una vez.
///
/// 120 archivos; se altera cada uno por turno y se exige que el verificador
/// señale ese y solo ese, y que al restaurarlo vuelva a dar íntegro. Son 240
/// contrastes: 120 que deben detectar y 120 que NO deben.
#[test]
fn simulacion_de_240_contrastes() {
    let dir = tempfile::tempdir().unwrap();
    const N: usize = 120;
    material(dir.path(), N);
    let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();
    assert!(recoleccion::contrastar(&acta.elementos, dir.path()).unwrap().is_empty());

    let mut detectados = 0;
    let mut limpios = 0;
    for i in 0..N {
        let nombre = format!("archivo{i:04}.txt");
        let ruta = if i % 3 == 0 {
            dir.path().join("sub").join(&nombre)
        } else {
            dir.path().join(&nombre)
        };
        let original = fs::read(&ruta).unwrap();

        // Alteración mínima: un solo byte, del tamaño que suele pasar
        // desapercibido en una revisión visual.
        let mut alterado = original.clone();
        alterado[0] ^= 0x01;
        fs::write(&ruta, &alterado).unwrap();

        let d = recoleccion::contrastar(&acta.elementos, dir.path()).unwrap();
        assert_eq!(d.len(), 1, "iteración {i}: se esperaba una sola discrepancia, hubo {d:?}");
        let esperada = if i % 3 == 0 { format!("sub/{nombre}") } else { nombre.clone() };
        match &d[0] {
            Discrepancia::Alterado { ruta, .. } => {
                assert_eq!(ruta, &esperada, "señaló el archivo equivocado");
                detectados += 1;
            }
            otro => panic!("iteración {i}: {otro:?}"),
        }

        fs::write(&ruta, &original).unwrap();
        assert!(
            recoleccion::contrastar(&acta.elementos, dir.path()).unwrap().is_empty(),
            "iteración {i}: falso positivo tras restaurar el archivo"
        );
        limpios += 1;
    }
    assert_eq!(detectados, N);
    assert_eq!(limpios, N);
}

/// Concurrencia con temporizador: firmar desde varias hebras a la vez.
///
/// Quipu dispara su autoprueba con `Once::call_once`, que no es reentrante y ya
/// causó un interbloqueo de 13 minutos en su historia. Sin temporizador, un
/// interbloqueo aquí parecería una prueba lenta.
#[test]
fn sellado_concurrente_sin_interbloqueo() {
    use std::sync::mpsc;
    use std::time::Duration;

    const HEBRAS: usize = 8;
    let (tx, rx) = mpsc::channel();

    for h in 0..HEBRAS {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let dir = tempfile::tempdir().unwrap();
            material(dir.path(), 12);
            let acta = sellado::sellar(dir.path(), &firmante(), &datos()).unwrap();
            let ok = acta.verificar_sello().is_ok()
                && recoleccion::contrastar(&acta.elementos, dir.path()).unwrap().is_empty();
            tx.send((h, ok)).unwrap();
        });
    }
    drop(tx);

    for _ in 0..HEBRAS {
        match rx.recv_timeout(Duration::from_secs(120)) {
            Ok((h, ok)) => assert!(ok, "la hebra {h} produjo un acta que no verifica"),
            Err(e) => panic!("interbloqueo o hebra muerta al sellar en paralelo: {e}"),
        }
    }
}

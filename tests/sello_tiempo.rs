// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Banco del sello de tiempo, sobre un token REAL.
//!
//! `fijos/sello_digicert.tsr` no es un token inventado: lo emitió la autoridad
//! de DigiCert el 26 de julio de 2026 sobre la firma de un acta de prueba. Se
//! guarda en el repositorio a propósito — un banco que solo prueba contra datos
//! que uno mismo fabricó no descubre las diferencias entre autoridades, que es
//! justo donde falló la primera versión de este código: el `TSTInfo` de DigiCert
//! traía 18 bytes de campos opcionales al final y el de FreeTSA, 300.
//!
//! La prueba contra una autoridad viva existe, pero es opt-in: una suite que
//! necesita internet para pasar acaba desactivada, o peor, se pone roja por un
//! corte de red y alguien aprende a ignorarla.

use tunjo::sello_tiempo;

/// SHA-256 de la firma que este token sella. Comprobado con `sha256sum` y con
/// `openssl ts -verify`, que además valida la cadena de certificados completa.
const HASH_SELLADO: [u8; 32] = [
    0xdd, 0xd5, 0x04, 0x70, 0x1c, 0x62, 0x4c, 0x96, 0x58, 0x26, 0xc7, 0x38, 0x75, 0xb6, 0x1e, 0x8d,
    0x70, 0x07, 0x3d, 0x58, 0xf1, 0x7b, 0xc2, 0xe2, 0xd2, 0xc4, 0x15, 0x94, 0x59, 0x64, 0xf3, 0xc8,
];

fn token() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fijos/sello_digicert.tsr"))
        .expect("el token de prueba debe estar en el repositorio")
}

#[test]
fn lee_un_token_real_de_una_autoridad_real() {
    let datos = sello_tiempo::verificar(&token(), &HASH_SELLADO).unwrap();

    // Contrastado contra lo que reporta `openssl ts -reply -text` del mismo
    // fichero: si estos valores cambian, o el parser se rompió o el fichero no
    // es el que era.
    assert_eq!(datos.fecha_utc, "2026-07-26T16:04:52Z");
    assert_eq!(datos.politica, "2.16.840.1.114412.7.1");
    assert_eq!(datos.serie, "6073a31245b3f025418eb65ed6e01355");
}

#[test]
fn un_token_valido_sobre_otro_dato_se_rechaza() {
    // El fallo más grave posible: aceptar un sello auténtico que no sella lo
    // nuestro. El token es legítimo; el hash, no el suyo.
    let mut otro = HASH_SELLADO;
    otro[0] ^= 0x01;
    let e = sello_tiempo::verificar(&token(), &otro).unwrap_err();
    assert!(e.to_string().contains("NO corresponde"), "{e}");
}

#[test]
fn la_basura_no_pasa_por_sello() {
    assert!(sello_tiempo::verificar(b"", &HASH_SELLADO).is_err());
    assert!(sello_tiempo::verificar(b"no soy DER", &HASH_SELLADO).is_err());
    // Un DER bien formado que no es un token tampoco.
    assert!(sello_tiempo::verificar(&[0x30, 0x03, 0x02, 0x01, 0x00], &HASH_SELLADO).is_err());
}

#[test]
fn un_token_truncado_no_se_interpreta_a_medias() {
    let completo = token();
    for corte in [10, 100, 1000, completo.len() - 1] {
        assert!(
            sello_tiempo::verificar(&completo[..corte], &HASH_SELLADO).is_err(),
            "un token cortado en {corte} bytes no puede darse por bueno"
        );
    }
}

#[test]
fn alterar_la_huella_dentro_del_token_se_detecta() {
    // Lo que esta herramienta SÍ promete: que el sello corresponda a nuestra
    // firma. Se busca la huella dentro del token y se le cambia un byte.
    let original = token();
    let pos = original
        .windows(32)
        .position(|v| v == HASH_SELLADO)
        .expect("la huella sellada tiene que estar dentro del token");

    for desplazamiento in 0..32 {
        let mut roto = original.clone();
        roto[pos + desplazamiento] ^= 0x01;
        assert!(
            sello_tiempo::verificar(&roto, &HASH_SELLADO).is_err(),
            "cambiar el byte {desplazamiento} de la huella debe invalidar el sello"
        );
    }
}

#[test]
fn alterar_la_firma_del_token_ahora_si_se_detecta() {
    // Esta prueba era una TRAMPA que no saltó, y merece quedar contada.
    //
    // Estaba escrita al revés —afirmaba `is_ok()` sobre un token con la firma
    // alterada— para fijar un límite declarado: «tunjo NO valida la firma CMS».
    // Su mensaje decía: «si esto ya falla, la validación CMS existe: actualiza el
    // límite declarado en el acta, en el README y en MARCO_JURIDICO §5». La idea
    // era buena: un guardián que obliga a corregir la documentación el día que la
    // realidad cambie.
    //
    // El 2026-07-30 la validación CMS llegó (`firma_cms`) y la trampa **siguió
    // verde**, porque apuntaba a `sello_tiempo::verificar`, que por diseño no
    // comprueba la firma. El guardián estaba mirando la puerta equivocada, y
    // durante horas siguió diciéndole al lector que el límite estaba vigente. Lo
    // cazó la cuarta revisión de seguridad, no la prueba.
    //
    // Ahora apunta a donde vive la comprobación, y afirma lo contrario.
    let mut roto = token();
    let n = roto.len();
    roto[n - 40] ^= 0xFF;

    // La fecha no importa aquí: se rechaza antes de mirarla.
    let e = tunjo::firma_cms::verificar_firma(&roto, "2026-07-26T16:04:52Z", &[])
        .expect_err("un token con la firma alterada NO puede verificar");
    let m = e.to_string();
    assert!(
        m.contains("NO es válida") || m.contains("no se pudo leer") || m.contains("no es un"),
        "debe rechazarse por la firma o por el DER que rompió, no por otra cosa: {m}"
    );

    // Y el token intacto sí pasa: si las dos fallaran, esto no probaría nada.
    tunjo::firma_cms::verificar_firma(&token(), "2026-07-26T16:04:52Z", &[])
        .expect("el token auténtico debe verificar");
}

/// Contra una autoridad viva. Opt-in:
///
/// ```bash
/// TUNJO_TSA=http://timestamp.digicert.com cargo test --release -- --ignored
/// ```
#[test]
#[ignore = "necesita red y una autoridad de sellado; se activa con TUNJO_TSA"]
fn pide_un_sello_a_una_autoridad_de_verdad() {
    let Ok(url) = std::env::var("TUNJO_TSA") else {
        panic!("define TUNJO_TSA con la URL de la autoridad");
    };
    let hash = sello_tiempo::hash_de(b"lo que sea que estemos sellando");
    let nonce = [0x5Au8; 16];

    let token = sello_tiempo::solicitar(&hash, &url, &nonce).expect("la autoridad debe responder");
    let datos = sello_tiempo::verificar(&token, &hash).expect("y su sello debe corresponder");
    assert!(datos.fecha_utc.ends_with('Z'), "la fecha va en UTC: {}", datos.fecha_utc);
    println!("sello obtenido de {url}: {} · política {}", datos.fecha_utc, datos.politica);
}

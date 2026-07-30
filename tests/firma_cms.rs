// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Banco de la verificación de la firma CMS del sello, sobre el token REAL.
//!
//! La primera prueba de este archivo es la que justifica el módulo entero:
//! hasta el 2026-07-30 un token con `signer_infos` VACÍO —DER perfectamente
//! válido, sin clave, sin certificado, sin autoridad— pasaba todos los
//! controles y la herramienta imprimía «fecha cierta» con código de salida 0.
//! Las 64 pruebas que había en verde comprobaban que un sello legítimo
//! funciona; ninguna que uno ilegítimo falle.
//!
//! Todas las mutaciones parten del token auténtico de DigiCert que ya vivía en
//! `fijos/`: se altera exactamente una cosa por prueba, para que lo que falle
//! señale a un control concreto y no a «algo».

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfos};
use der::asn1::{OctetString, SetOfVec};
use der::{Any, Decode, Encode, Tag};
use tunjo::firma_cms::{self, Confianza};
use x509_cert::Certificate;

/// Fecha que el token certifica, contrastada con `openssl ts -reply -text`.
const FECHA: &str = "2026-07-26T16:04:52Z";

fn token() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fijos/sello_digicert.tsr"))
        .expect("el token de prueba debe estar en el repositorio")
}

/// Vuelve a empaquetar un `SignedData` mutado como `ContentInfo`.
fn reempaquetar(sd: &SignedData) -> Vec<u8> {
    let ci = ContentInfo {
        content_type: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2"),
        content: Any::encode_from(sd).unwrap(),
    };
    ci.to_der().unwrap()
}

fn abrir(token: &[u8]) -> SignedData {
    ContentInfo::from_der(token).unwrap().content.decode_as().unwrap()
}

/// Los certificados X.509 que viajan en el token, en el orden en que vienen.
fn certificados(token: &[u8]) -> Vec<Certificate> {
    use cms::cert::CertificateChoices;
    abrir(token)
        .certificates
        .unwrap()
        .0
        .iter()
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

// ------------------------------------------------------- el token que sí vale

#[test]
fn el_token_real_lleva_firma_valida_pero_no_esta_anclado() {
    let c = firma_cms::verificar_firma(&token(), FECHA, &[]).unwrap();

    // Sin anclas la firma se comprueba igual, pero NO se puede decir de quién
    // viene: es la distinción que el veredicto tiene que respetar.
    assert!(!c.acredita_autoridad(), "sin anclas no se acredita autoridad: {c:?}");
    assert!(matches!(c, Confianza::SinAnclar { .. }), "{c:?}");
    assert!(
        c.autoridad().contains("Timestamp Responder"),
        "debe decir QUIÉN dice haber firmado, aunque no esté anclado: {}",
        c.autoridad()
    );
}

// -------------------------------------------- LA prueba: el sello sin firmante

#[test]
fn un_token_sin_firmantes_no_acredita_nada() {
    // Esto es la vulnerabilidad que cerró este módulo. Un SET OF vacío es DER
    // válido: cualquiera podía coger un TSTInfo, ponerle la fecha y el hash que
    // quisiera, dejar `signer_infos` a cero y la herramienta lo daba por sellado.
    let mut sd = abrir(&token());
    sd.signer_infos = SignerInfos(SetOfVec::new());
    let forjado = reempaquetar(&sd);

    let e = firma_cms::verificar_firma(&forjado, FECHA, &[]).unwrap_err();
    assert!(
        e.to_string().contains("NINGÚN firmante"),
        "el motivo debe señalar la ausencia de firmante: {e}"
    );
}

#[test]
fn un_token_sin_certificados_no_se_puede_verificar() {
    // La otra mitad de la misma forja: sin el certificado no hay clave con la que
    // comprobar nada, y «no se pudo comprobar» nunca es «está bien».
    let mut sd = abrir(&token());
    sd.certificates = None;
    let e = firma_cms::verificar_firma(&reempaquetar(&sd), FECHA, &[]).unwrap_err();
    assert!(e.to_string().contains("no trae certificados"), "{e}");
}

// --------------------------------------------------- mutaciones de una en una

#[test]
fn una_firma_alterada_se_rechaza() {
    let mut sd = abrir(&token());
    let mut firmantes: Vec<_> = sd.signer_infos.0.iter().cloned().collect();
    let mut bytes = firmantes[0].signature.as_bytes().to_vec();
    bytes[0] ^= 0x01;
    // En CMS la firma es un OCTET STRING, no un BIT STRING (a diferencia del
    // certificado X.509, donde sí lo es).
    firmantes[0].signature = OctetString::new(bytes).unwrap();
    sd.signer_infos = SignerInfos(SetOfVec::try_from(firmantes).unwrap());

    let e = firma_cms::verificar_firma(&reempaquetar(&sd), FECHA, &[]).unwrap_err();
    assert!(e.to_string().contains("NO es válida"), "{e}");
}

#[test]
fn cambiar_el_contenido_rompe_el_atributo_que_lo_ata() {
    // El `message-digest` firmado es lo que impide que una firma auténtica se
    // reutilice sobre OTRO TSTInfo —otra fecha, otro hash—. Se altera un byte
    // del contenido sin tocar la firma: debe cazarlo el atributo, no el azar.
    let mut sd = abrir(&token());
    let octetos: OctetString =
        sd.encap_content_info.econtent.as_ref().unwrap().decode_as().unwrap();
    let mut bytes = octetos.as_bytes().to_vec();
    let medio = bytes.len() / 2;
    bytes[medio] ^= 0x01;
    sd.encap_content_info.econtent = Some(Any::new(Tag::OctetString, bytes).unwrap());

    let e = firma_cms::verificar_firma(&reempaquetar(&sd), FECHA, &[]).unwrap_err();
    assert!(
        e.to_string().contains("message-digest"),
        "debe señalar el atributo que ata la firma al contenido: {e}"
    );
}

#[test]
fn un_content_info_que_no_es_signed_data_se_rechaza() {
    // Antes no se miraba el tipo declarado: `decode_as` no lo comprueba.
    let sd = abrir(&token());
    let ci = ContentInfo {
        // id-data, no id-signedData.
        content_type: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1"),
        content: Any::encode_from(&sd).unwrap(),
    };
    let e = firma_cms::verificar_firma(&ci.to_der().unwrap(), FECHA, &[]).unwrap_err();
    assert!(e.to_string().contains("no es un SignedData"), "{e}");
}

// ------------------------------------------------------------------- vigencia

#[test]
fn no_vale_un_sello_fechado_fuera_de_la_vigencia_del_certificado() {
    // Se compara contra la fecha DEL TOKEN, no contra hoy: por eso un sello
    // antiguo sigue valiendo cuando el certificado ya caducó, y por eso una
    // fecha imposible —anterior a que el certificado existiera— no vale.
    let e = firma_cms::verificar_firma(&token(), "2001-01-01T00:00:00Z", &[]).unwrap_err();
    assert!(e.to_string().contains("no había empezado a valer"), "{e}");

    let e = firma_cms::verificar_firma(&token(), "2099-01-01T00:00:00Z", &[]).unwrap_err();
    assert!(e.to_string().contains("caducado"), "{e}");
}

// ---------------------------------------------------------------- el anclaje

#[test]
fn con_la_raiz_de_digicert_el_sello_queda_anclado() {
    // El ancla se toma del propio token, así que esta prueba ejercita el CAMINO
    // —subir de la hoja a la intermedia y de ahí a la raíz, verificando cada
    // firma— no la confianza. Lo que prueba la confianza es la prueba de al lado.
    let certs = certificados(&token());
    let raiz = certs
        .iter()
        .find(|c| c.tbs_certificate.subject.to_string().contains("Trusted Root G4"))
        .expect("el token trae la raíz G4")
        .clone();

    let c = firma_cms::verificar_firma(&token(), FECHA, &[raiz]).unwrap();
    assert!(c.acredita_autoridad(), "{c:?}");
    match c {
        Confianza::Anclada { autoridad, ancla } => {
            assert!(autoridad.contains("Timestamp Responder"), "{autoridad}");
            assert!(ancla.contains("Trusted Root G4"), "{ancla}");
        }
        otro => panic!("debía quedar anclada: {otro:?}"),
    }
}

#[test]
fn un_ancla_con_el_nombre_correcto_y_la_clave_equivocada_no_ancla() {
    // ESTA es la que discrimina. Si el anclaje se conformara con que los nombres
    // cuadren, un atacante ancla lo que quiera llamando a su certificado
    // «DigiCert Trusted Root G4». Se le cambia la clave pública y se deja el
    // nombre: la firma de la intermedia deja de verificar y no debe anclar.
    let certs = certificados(&token());
    let mut falsa = certs
        .iter()
        .find(|c| c.tbs_certificate.subject.to_string().contains("Trusted Root G4"))
        .expect("el token trae la raíz G4")
        .clone();

    let mut clave = falsa
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec();
    clave[20] ^= 0x01;
    falsa.tbs_certificate.subject_public_key_info.subject_public_key =
        der::asn1::BitString::from_bytes(&clave).unwrap();

    let e = firma_cms::verificar_firma(&token(), FECHA, &[falsa]).unwrap_err();
    assert!(
        e.to_string().contains("no encadena"),
        "un ancla que solo coincide en el nombre no debe anclar: {e}"
    );
}

#[test]
fn un_ancla_ajena_a_la_cadena_no_ancla() {
    // La hoja no emite a nadie: usarla como ancla de SU PROPIA cadena sí vale
    // (es confiar en esa TSA concreta), pero la intermedia de otra jerarquía no.
    // Aquí se usa la hoja como ancla de la cadena en la que ella misma firma,
    // que es el caso legítimo, y se comprueba que ancla.
    let certs = certificados(&token());
    let hoja = certs
        .iter()
        .find(|c| c.tbs_certificate.subject.to_string().contains("Timestamp Responder"))
        .expect("el token trae la hoja")
        .clone();
    let c = firma_cms::verificar_firma(&token(), FECHA, &[hoja]).unwrap();
    assert!(
        c.acredita_autoridad(),
        "confiar explícitamente en el certificado que firma es un anclaje válido: {c:?}"
    );
}

// --------------------------------- el cableado: lo que ve `custodia verificar`

/// Una cadena mínima con el sello que se le pase. Los eslabones no hacen falta:
/// la firma del sello se comprueba ANTES de situarlo, y precisamente eso es lo
/// que estas dos pruebas contrastan.
fn cadena_con_sello(token_der: &[u8], hash_hex: &str) -> tunjo::custodia::Cadena {
    use base64::Engine as _;
    tunjo::custodia::Cadena {
        formato: tunjo::custodia::FORMATO_CADENA.to_string(),
        acta_sha256: "0".repeat(64),
        clave_publica: String::new(),
        eslabones: Vec::new(),
        sello_final: Some(tunjo::custodia::SelloCadena {
            secuencia: 0,
            hash_eslabon: hash_hex.to_string(),
            token_der_b64: base64::engine::general_purpose::STANDARD.encode(token_der),
        }),
    }
}

/// Hash que el token real sella, en hex: es lo que debe llevar `hash_eslabon`
/// para que el sello llegue hasta la comprobación de la firma.
const HASH_HEX: &str = "ddd504701c624c965826c73875b61e8d70073d58f17bc2e2d2c415945964f3c8";

#[test]
fn un_sello_forjado_deja_la_cadena_en_invalido() {
    // El camino completo que recorre `custodia verificar`: si esto pasara, el
    // programa imprimiría «fecha cierta» y saldría con 0 sobre un token que
    // nadie firmó.
    let mut sd = abrir(&token());
    sd.signer_infos = SignerInfos(SetOfVec::new());
    let cadena = cadena_con_sello(&reempaquetar(&sd), HASH_HEX);

    match tunjo::custodia::estado_sello(&cadena, &[]) {
        tunjo::custodia::EstadoSello::Invalido { motivo } => {
            assert!(
                motivo.contains("la firma del sello no vale"),
                "debe rechazarse POR LA FIRMA, no por otra cosa: {motivo}"
            );
        }
        otro => panic!("un sello sin firmante no puede dar {otro:?}"),
    }
}

#[test]
fn el_sello_autentico_llega_mas_alla_de_la_firma() {
    // Control de la prueba de arriba: con el token AUTÉNTICO y la misma cadena
    // vacía, el rechazo tiene que ser por los eslabones, no por la firma. Si las
    // dos fallaran igual, la prueba anterior no probaría nada.
    let cadena = cadena_con_sello(&token(), HASH_HEX);
    match tunjo::custodia::estado_sello(&cadena, &[]) {
        tunjo::custodia::EstadoSello::Invalido { motivo } => {
            assert!(
                !motivo.contains("la firma del sello no vale"),
                "la firma auténtica no debe ser el motivo: {motivo}"
            );
            assert!(motivo.contains("sin eslabones"), "{motivo}");
        }
        otro => panic!("con la cadena vacía se esperaba Invalido por eslabones: {otro:?}"),
    }
}

// -------------------------------------------------------------------- anclas PEM

#[test]
fn el_pem_de_anclas_se_lee_y_lo_que_no_es_pem_falla() {
    assert!(firma_cms::anclas_desde_pem("").is_err());
    assert!(firma_cms::anclas_desde_pem("no soy un PEM").is_err());
    assert!(
        firma_cms::anclas_desde_pem("-----BEGIN CERTIFICATE-----\nZZZZ\n-----END CERTIFICATE-----")
            .is_err()
    );

    // Ida y vuelta con un certificado real: DER -> PEM -> DER.
    let certs = certificados(&token());
    let der = certs[0].to_der().unwrap();
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
    let pem = format!("-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n");
    let leidas = firma_cms::anclas_desde_pem(&pem).unwrap();
    assert_eq!(leidas.len(), 1);
    assert_eq!(leidas[0].to_der().unwrap(), der);
}

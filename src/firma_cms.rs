// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Juan Carlos Isaza Arenas

//! Verificación de la firma CMS de un token RFC 3161.
//!
//! # Por qué existe este módulo
//!
//! Hasta el 2026-07-30 `sello_tiempo::verificar` comprobaba dos cosas del token
//! —que el algoritmo de huella fuera SHA-256 y que el `messageImprint`
//! correspondiera al hash sellado— y **ninguna sobre quién lo firmó**. La
//! cabecera del módulo lo declaraba y el acta lo imprimía, así que era una
//! limitación honesta: el sello era un dato informativo.
//!
//! Dejó de serlo cuando `custodia sello` empezó a apoyar un VEREDICTO en él
//! («la cadena está completa hasta aquí», con código de salida). Un
//! `SignedData` con `signer_infos` VACÍO parsea sin problema, de modo que
//! cualquiera con un editor DER podía fijar el eslabón y la fecha que quisiera
//! sin clave, sin certificado y sin hablar con ninguna autoridad. El control
//! anti-truncación era forjable justo por quien tenía que constreñir.
//!
//! # Qué comprueba, y en qué orden
//!
//! 1. Que el `ContentInfo` sea `id-signedData` (antes no se miraba).
//! 2. Que haya **exactamente un** firmante. Cero es la forja; más de uno es una
//!    ambigüedad que esta herramienta no va a juzgar en silencio.
//! 3. Que el certificado del firmante VIAJE en el token y se corresponda con el
//!    `SignerIdentifier`.
//! 4. Que ese certificado lleve el `extendedKeyUsage` **id-kp-timeStamping**: sin
//!    él no es una autoridad de sellado, diga lo que diga su nombre.
//! 5. Que los atributos firmados existan y digan lo que deben: `content-type` =
//!    `id-ct-TSTInfo` y `message-digest` = huella del contenido encapsulado.
//! 6. Que la **firma** sobre el DER de los atributos firmados sea válida con la
//!    clave pública de ese certificado.
//! 7. Que el certificado estuviera vigente en el instante que el propio token
//!    dice certificar.
//!
//! # El límite, y va en el veredicto, no en un comentario
//!
//! Los pasos 1-7 no distinguen a una autoridad real de un certificado que el
//! adversario se fabricó hace un minuto: un autofirmado con el EKU correcto pasa
//! todo lo anterior. Lo que separa una cosa de otra es **anclar** el certificado
//! a algo en lo que el verificador haya decidido confiar, y esa decisión no la
//! puede tomar esta herramienta por él (ver [`verificar_firma`] y
//! `Confianza::SinAnclar`). Por eso la ausencia de ancla NO se rellena con un
//! almacén por defecto: se dice.
//!
//! Lo que sigue fuera de alcance, y también se dice: revocación (CRL/OCSP),
//! restricciones de nombre y políticas de certificación. Para una validación
//! completa, `openssl ts -verify`.

use anyhow::{Context, Result, bail};
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Decode, Encode};
use x509_cert::Certificate;
use x509_cert::attr::Attribute;

// ------------------------------------------------------------------------ OIDs

/// `id-signedData` — el único tipo de `ContentInfo` que un token puede tener.
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// `id-ct-TSTInfo`.
const OID_TSTINFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
/// Atributo firmado `content-type`.
const OID_ATTR_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// Atributo firmado `message-digest`.
const OID_ATTR_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// Extensión `extKeyUsage`.
const OID_EXT_EKU: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// Extensión `basicConstraints`: dice si un certificado puede EMITIR otros.
const OID_EXT_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// Extensión `keyUsage`.
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// `id-kp-timeStamping` — RFC 3161 §2.3 lo exige en el certificado de la TSA.
const OID_KP_TIMESTAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

// Huellas.
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

// Firmas.
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
/// `rsaEncryption`: algunas TSA lo ponen aquí y la huella se toma de `digest_alg`.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Curvas de la clave pública.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

// --------------------------------------------------------------------- salidas

/// Grado de confianza que se puede afirmar de un token, y solo eso.
///
/// La distinción es el punto entero del módulo: `Anclada` y `SinAnclar` tienen
/// la MISMA firma válida, y la diferencia no es criptográfica sino de a quién
/// decidió creer el verificador.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confianza {
    /// Firma válida y el certificado del firmante encadena hasta un ancla que
    /// aportó el verificador. Es lo único que acredita QUIÉN fechó.
    Anclada {
        /// Sujeto del certificado que firmó, tal como viene en el token.
        autoridad: String,
        /// Sujeto del ancla en la que termina la cadena.
        ancla: String,
    },
    /// Firma válida contra el certificado que viaja EN el token, sin ancla con
    /// la que contrastarlo. No distingue una autoridad real de un autofirmado
    /// que el adversario acaba de emitir: acredita que el token es coherente,
    /// **no** de quién viene.
    SinAnclar {
        /// Sujeto del certificado que firmó, tal como viene en el token.
        autoridad: String,
    },
}

impl Confianza {
    /// `true` solo cuando la identidad de la autoridad está acreditada.
    pub fn acredita_autoridad(&self) -> bool {
        matches!(self, Confianza::Anclada { .. })
    }

    /// Sujeto del certificado firmante, para poder decir en la salida quién dice
    /// haber fechado incluso cuando no está anclado.
    pub fn autoridad(&self) -> &str {
        match self {
            Confianza::Anclada { autoridad, .. } | Confianza::SinAnclar { autoridad } => autoridad,
        }
    }
}

// ------------------------------------------------------------------ verificación

/// Verifica la firma CMS de un token de sello y, si se aportan anclas, la ancla.
///
/// `instante_utc` es la fecha que el propio token certifica: se usa para exigir
/// que el certificado estuviera vigente ENTONCES, no ahora. Un token de 2020
/// firmado con un certificado que caducó en 2021 sigue siendo bueno; lo que no
/// vale es uno firmado con un certificado que ya estaba caducado al firmar.
///
/// `anclas` son los certificados en los que el verificador ha decidido confiar.
/// Si viene vacío, la función NO falla —el token puede estar perfectamente
/// firmado— pero devuelve [`Confianza::SinAnclar`], y quien la llame no puede
/// afirmar de quién viene la fecha. Deliberadamente no hay almacén por defecto:
/// rellenar esa decisión sería inventarse la confianza del verificador.
///
/// Devuelve `Err` cuando el token **no** está correctamente firmado. Ese caso no
/// es una advertencia: es un token que no acredita nada.
pub fn verificar_firma(
    token_der: &[u8],
    instante_utc: &str,
    anclas: &[Certificate],
) -> Result<Confianza> {
    let ci = ContentInfo::from_der(token_der)
        .context("el token de sello no es un ContentInfo válido")?;
    // ANTES no se miraba: `decode_as` no comprueba el tipo declarado, así que un
    // ContentInfo que dice ser cualquier cosa colaba mientras el cuerpo encajara.
    if ci.content_type != OID_SIGNED_DATA {
        bail!(
            "el token no es un SignedData sino {} — no puede llevar la firma de ninguna autoridad",
            ci.content_type
        );
    }
    let firmado: SignedData = ci
        .content
        .decode_as()
        .context("el token de sello no contiene un SignedData")?;

    // Exactamente un firmante. CERO es la forja que este módulo existe para
    // cortar: un SET OF vacío es DER válido y pasaba todos los controles viejos.
    let firmantes: Vec<&SignerInfo> = firmado.signer_infos.0.iter().collect();
    let firmante = match firmantes.as_slice() {
        [uno] => *uno,
        [] => bail!(
            "el token no lleva NINGÚN firmante: no lo emitió ninguna autoridad, \
             solo lo escribió alguien"
        ),
        varios => bail!(
            "el token lleva {} firmantes; un sello de tiempo tiene uno y esta \
             herramienta no elige por ti cuál vale",
            varios.len()
        ),
    };

    let certificados = certificados_del_token(&firmado)?;
    let cert = localizar_firmante(&certificados, &firmante.sid)
        .context("el certificado del firmante no viaja en el token; sin él no hay nada que verificar")?;

    exigir_eku_sellado(cert)?;

    // Atributos firmados: obligatorios para una TSA, y son lo que ata la firma
    // al TSTInfo. Sin ellos la firma cubriría el contenido directamente y no
    // habría forma de saber que el firmante quiso decir «esto es un TSTInfo».
    let atributos = firmante
        .signed_attrs
        .as_ref()
        .context("el token no lleva atributos firmados; no ata la firma al TSTInfo")?;

    let contenido = contenido_encapsulado(&firmado)?;
    comprobar_atributos(atributos, &firmante.digest_alg.oid, &contenido)?;

    // RFC 5652 §5.4: se firma el DER del SET OF de atributos, NO la etiqueta
    // implícita [0] con la que viajan.
    let firmado_der = atributos
        .to_der()
        .context("no se pudieron recodificar los atributos firmados")?;

    verificar_firma_sobre(
        cert,
        &firmante.signature_algorithm.oid,
        &firmante.digest_alg.oid,
        &firmado_der,
        firmante.signature.as_bytes(),
    )?;

    exigir_vigencia(cert, instante_utc)?;

    // Neutralizado AQUÍ, donde nace, y no en cada sitio que lo imprima. Hoy el
    // `Display` de `x509-cert` escapa los controles en hexadecimal conforme a
    // RFC 4514, así que no era explotable — pero esa garantía vivía en el código de
    // un tercero y no se podía leer en el nuestro. Séptima revisión.
    let autoridad = crate::texto::plano(&cert.tbs_certificate.subject.to_string());
    match anclar(cert, &certificados, anclas, instante_utc)? {
        Some(ancla) => Ok(Confianza::Anclada { autoridad, ancla }),
        None => Ok(Confianza::SinAnclar { autoridad }),
    }
}

// ------------------------------------------------------------------- auxiliares

fn certificados_del_token(firmado: &SignedData) -> Result<Vec<Certificate>> {
    use cms::cert::CertificateChoices;
    let Some(conjunto) = &firmado.certificates else {
        bail!("el token no trae certificados: se pidió `certReq`, así que una autoridad real los incluye");
    };
    let mut salida = Vec::new();
    for elegido in conjunto.0.iter() {
        // Solo se entienden certificados X.509. Un `other`/`v1AttrCert` no se
        // trata como si fuera uno: se ignora, y si al final no queda ninguno el
        // llamante falla por falta de certificado, no por confusión de tipos.
        if let CertificateChoices::Certificate(c) = elegido {
            salida.push(c.clone());
        }
    }
    if salida.is_empty() {
        bail!("el token no trae ningún certificado X.509 con el que verificar la firma");
    }
    Ok(salida)
}

/// Encuentra el certificado que el `SignerInfo` dice haber usado.
fn localizar_firmante<'a>(
    certificados: &'a [Certificate],
    sid: &SignerIdentifier,
) -> Option<&'a Certificate> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => certificados.iter().find(|c| {
            c.tbs_certificate.serial_number == ias.serial_number
                && c.tbs_certificate.issuer == ias.issuer
        }),
        SignerIdentifier::SubjectKeyIdentifier(ski) => certificados.iter().find(|c| {
            extension(c, &ObjectIdentifier::new_unwrap("2.5.29.14"))
                .and_then(|bytes| OctetString::from_der(bytes).ok())
                .map(|o| o.as_bytes() == ski.0.as_bytes())
                .unwrap_or(false)
        }),
    }
}

/// Devuelve el contenido de una extensión por OID, sin interpretarlo.
fn extension<'a>(cert: &'a Certificate, oid: &ObjectIdentifier) -> Option<&'a [u8]> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| &e.extn_id == oid)
        .map(|e| e.extn_value.as_bytes())
}

/// RFC 3161 §2.3: el certificado de la TSA debe llevar `id-kp-timeStamping`.
///
/// Se exige su PRESENCIA. No se exige que sea el único uso ni que la extensión
/// venga marcada como crítica: ambas cosas las manda la norma, pero rechazar por
/// ellas descartaría autoridades reales por un defecto de forma, y lo que aquí
/// se decide es si esta clave tenía permiso para fechar. Lo que sí se rechaza es
/// lo que significa otra cosa: un certificado sin ese uso NO es de sellado.
fn exigir_eku_sellado(cert: &Certificate) -> Result<()> {
    let Some(bytes) = extension(cert, &OID_EXT_EKU) else {
        bail!(
            "el certificado del firmante no declara extendedKeyUsage: no es un \
             certificado de autoridad de sellado"
        );
    };
    let usos: Vec<ObjectIdentifier> = Vec::<ObjectIdentifier>::from_der(bytes)
        .context("el extendedKeyUsage del certificado no se pudo leer")?;
    if !usos.contains(&OID_KP_TIMESTAMPING) {
        bail!(
            "el certificado del firmante no lleva id-kp-timeStamping: esa clave no \
             está autorizada a fechar, aunque la firma cuadre"
        );
    }
    Ok(())
}

fn contenido_encapsulado(firmado: &SignedData) -> Result<Vec<u8>> {
    let encap = &firmado.encap_content_info;
    if encap.econtent_type != OID_TSTINFO {
        bail!(
            "el token no encapsula un TSTInfo sino {} — no es un sello RFC 3161",
            encap.econtent_type
        );
    }
    let contenido = encap
        .econtent
        .as_ref()
        .context("el token de sello viene sin contenido")?;
    let octetos: OctetString = contenido
        .decode_as()
        .context("el contenido del token no es un OCTET STRING")?;
    Ok(octetos.as_bytes().to_vec())
}

/// Comprueba que los atributos firmados dicen lo que deben.
///
/// Son los dos que RFC 5652 exige cuando hay `signedAttrs`, y son justo los que
/// atan la firma a ESTE contenido: sin `message-digest` la firma valdría para
/// cualquier TSTInfo, y sin `content-type` valdría para cualquier tipo de
/// contenido.
fn comprobar_atributos(
    atributos: &SetOfVec<Attribute>,
    huella_oid: &ObjectIdentifier,
    contenido: &[u8],
) -> Result<()> {
    let valor_unico = |oid: &ObjectIdentifier| -> Option<Any> {
        atributos
            .iter()
            .find(|a| &a.oid == oid)
            .and_then(|a| match a.values.len() {
                // Un atributo con varios valores no se «elige»: se rechaza fuera.
                1 => a.values.iter().next().cloned(),
                _ => None,
            })
    };

    let tipo = valor_unico(&OID_ATTR_CONTENT_TYPE)
        .context("falta el atributo firmado content-type, o trae más de un valor")?;
    let tipo: ObjectIdentifier = tipo
        .decode_as()
        .context("el atributo content-type no es un OID")?;
    if tipo != OID_TSTINFO {
        bail!("el atributo firmado content-type dice {tipo}, no id-ct-TSTInfo");
    }

    let digest = valor_unico(&OID_ATTR_MESSAGE_DIGEST)
        .context("falta el atributo firmado message-digest, o trae más de un valor")?;
    let digest: OctetString = digest
        .decode_as()
        .context("el atributo message-digest no es un OCTET STRING")?;

    let calculado = huella(huella_oid, contenido)?;
    if digest.as_bytes() != calculado.as_slice() {
        bail!(
            "el atributo firmado message-digest no corresponde al contenido del \
             token: la firma cubre OTRO TSTInfo"
        );
    }
    Ok(())
}

/// Huella del contenido con el algoritmo que declara el firmante.
///
/// Un OID desconocido es error, nunca «se asume SHA-256»: suponer aquí sería
/// dar por válida una firma que no se ha comprobado.
fn huella(oid: &ObjectIdentifier, datos: &[u8]) -> Result<Vec<u8>> {
    use sha2_010::Digest as _;
    Ok(match *oid {
        OID_SHA256 => sha2_010::Sha256::digest(datos).to_vec(),
        OID_SHA384 => sha2_010::Sha384::digest(datos).to_vec(),
        OID_SHA512 => sha2_010::Sha512::digest(datos).to_vec(),
        otro => bail!("algoritmo de huella no soportado en el sello: {otro}"),
    })
}

/// Verifica la firma con la clave pública del certificado.
///
/// Solo RSA PKCS#1 v1.5 y ECDSA sobre P-256/P-384, que es lo que usan las
/// autoridades reales. Cualquier otra combinación es error explícito: una firma
/// que no se sabe verificar no es una firma válida.
fn verificar_firma_sobre(
    cert: &Certificate,
    algoritmo: &ObjectIdentifier,
    huella_oid: &ObjectIdentifier,
    mensaje: &[u8],
    firma: &[u8],
) -> Result<()> {
    let spki = &cert.tbs_certificate.subject_public_key_info;

    // Con `rsaEncryption` el algoritmo no dice la huella; la toma de digest_alg.
    let huella_efectiva = match *algoritmo {
        OID_RSA_SHA256 | OID_ECDSA_SHA256 => OID_SHA256,
        OID_RSA_SHA384 | OID_ECDSA_SHA384 => OID_SHA384,
        OID_RSA_SHA512 => OID_SHA512,
        OID_RSA_ENCRYPTION => *huella_oid,
        otro => bail!(
            "algoritmo de firma no soportado en el sello: {otro}. No se da por \
             buena una firma que no se ha comprobado"
        ),
    };

    let es_ecdsa = matches!(*algoritmo, OID_ECDSA_SHA256 | OID_ECDSA_SHA384);
    if es_ecdsa {
        verificar_ecdsa(spki, &huella_efectiva, mensaje, firma)
    } else {
        verificar_rsa(spki, &huella_efectiva, mensaje, firma)
    }
}

fn verificar_rsa(
    spki: &spki::SubjectPublicKeyInfoOwned,
    huella_oid: &ObjectIdentifier,
    mensaje: &[u8],
    firma: &[u8],
) -> Result<()> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};

    let clave = RsaPublicKey::from_pkcs1_der(spki.subject_public_key.raw_bytes())
        .context("la clave pública RSA del certificado no se pudo leer")?;
    let firma = Signature::try_from(firma).context("la firma RSA no tiene la forma esperada")?;

    let resultado = match *huella_oid {
        OID_SHA256 => {
            VerifyingKey::<sha2_010::Sha256>::new(clave).verify(mensaje, &firma)
        }
        OID_SHA384 => {
            VerifyingKey::<sha2_010::Sha384>::new(clave).verify(mensaje, &firma)
        }
        OID_SHA512 => {
            VerifyingKey::<sha2_010::Sha512>::new(clave).verify(mensaje, &firma)
        }
        otro => bail!("huella no soportada para firma RSA: {otro}"),
    };
    resultado.map_err(|_| {
        anyhow::anyhow!(
            "la firma del token NO es válida para el certificado que trae: \
             el sello está manipulado o no lo emitió esa clave"
        )
    })
}

fn verificar_ecdsa(
    spki: &spki::SubjectPublicKeyInfoOwned,
    huella_oid: &ObjectIdentifier,
    mensaje: &[u8],
    firma: &[u8],
) -> Result<()> {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        bail!("el certificado dice firmar con ECDSA pero su clave no es de curva elíptica");
    }
    let curva: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .context("el certificado no declara la curva de su clave ECDSA")?
        .decode_as()
        .context("la curva declarada en el certificado no se pudo leer")?;

    let punto = spki.subject_public_key.raw_bytes();
    let malo = || {
        anyhow::anyhow!(
            "la firma del token NO es válida para el certificado que trae: \
             el sello está manipulado o no lo emitió esa clave"
        )
    };

    match (curva, *huella_oid) {
        (OID_P256, OID_SHA256) => {
            use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let vk = VerifyingKey::from_sec1_bytes(punto)
                .context("la clave pública P-256 del certificado no se pudo leer")?;
            let s = Signature::from_der(firma).context("la firma ECDSA no es DER válido")?;
            vk.verify(mensaje, &s).map_err(|_| malo())
        }
        (OID_P384, OID_SHA384) => {
            use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
            let vk = VerifyingKey::from_sec1_bytes(punto)
                .context("la clave pública P-384 del certificado no se pudo leer")?;
            let s = Signature::from_der(firma).context("la firma ECDSA no es DER válido")?;
            vk.verify(mensaje, &s).map_err(|_| malo())
        }
        (c, h) => bail!(
            "combinación ECDSA no soportada: curva {c} con huella {h}. No se da por \
             buena una firma que no se ha comprobado"
        ),
    }
}

/// Exige que el certificado estuviera vigente en el instante que sella.
///
/// Se compara contra la fecha DEL TOKEN, no contra hoy: un sello de 2020 sigue
/// acreditando aunque el certificado haya caducado después —es justo para eso
/// para lo que sirve—. Lo que no vale es firmar con un certificado que ya estaba
/// caducado, o que aún no había empezado a valer.
fn exigir_vigencia(cert: &Certificate, instante_utc: &str) -> Result<()> {
    let momento = chrono::DateTime::parse_from_rfc3339(instante_utc)
        .map(|d| d.timestamp())
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(instante_utc, "%Y-%m-%d %H:%M:%S UTC")
                .map(|d| d.and_utc().timestamp())
        })
        .with_context(|| {
            format!("no se pudo interpretar la fecha del token ({instante_utc}) para \
                     comprobar la vigencia del certificado")
        })?;

    let desde = cert.tbs_certificate.validity.not_before.to_unix_duration().as_secs() as i64;
    let hasta = cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs() as i64;

    if momento < desde {
        bail!(
            "el certificado de la autoridad no había empezado a valer cuando dice \
             haber sellado"
        );
    }
    if momento > hasta {
        bail!("el certificado de la autoridad ya estaba caducado cuando dice haber sellado");
    }
    Ok(())
}

/// Intenta encadenar el certificado del firmante hasta una de las anclas.
///
/// Camino corto y declarado: se sube por coincidencia de emisor sobre los
/// certificados que vienen EN el token, verificando cada firma y la vigencia de
/// cada eslabón, hasta topar con un ancla. No es validación RFC 5280 completa
/// —sin revocación, sin restricciones de nombre, sin políticas— y eso está en la
/// cabecera del módulo y en la salida del programa.
///
/// Devuelve `Ok(None)` cuando no se aportaron anclas: no es un fallo, es que
/// nadie dijo en quién confiar.
fn anclar(
    firmante: &Certificate,
    del_token: &[Certificate],
    anclas: &[Certificate],
    instante_utc: &str,
) -> Result<Option<String>> {
    if anclas.is_empty() {
        return Ok(None);
    }

    let mut actual = firmante.clone();
    // Tres saltos cubre cualquier jerarquía de TSA real (hoja → intermedia →
    // raíz); el tope existe para que un lote de certificados con un ciclo no
    // convierta esto en un bucle. `recorridos` es el índice porque cada vuelta
    // sube exactamente un peldaño: es lo que limita `pathLenConstraint`.
    for recorridos in 0..3usize {
        // ¿Alguna ancla EMITIÓ el certificado actual? Para emitir hay que poder
        // emitir: el nombre y la firma no bastan (ver `exigir_puede_emitir`).
        for ancla in anclas {
            if ancla.tbs_certificate.subject == actual.tbs_certificate.issuer
                && exigir_puede_emitir(ancla, recorridos).is_ok()
                && firma_de_certificado_valida(&actual, ancla).is_ok()
            {
                exigir_vigencia(ancla, instante_utc)?;
                // Mismo motivo que en `autoridad`: se neutraliza donde nace.
                return Ok(Some(crate::texto::plano(&ancla.tbs_certificate.subject.to_string())));
            }
        }
        // ¿El ancla ES el certificado actual? Aquí NO se exige poder emitir: el
        // verificador está confiando en ESE certificado concreto, no usándolo
        // para avalar a otro. Confiar en la hoja de una TSA que conoces es un
        // anclaje legítimo, y exigirle `cA` la rechazaría por no ser lo que no
        // pretende ser.
        if let Some(ancla) = anclas.iter().find(|a| {
            a.tbs_certificate.subject == actual.tbs_certificate.subject
                && a.tbs_certificate.subject_public_key_info
                    == actual.tbs_certificate.subject_public_key_info
        }) {
            return Ok(Some(ancla.tbs_certificate.subject.to_string()));
        }
        // Si no, se sube un peldaño con lo que venga en el token — y solo con un
        // certificado que de verdad sea autoridad certificadora.
        let Some(padre) = del_token.iter().find(|c| {
            c.tbs_certificate.subject == actual.tbs_certificate.issuer
                && c.tbs_certificate.subject != actual.tbs_certificate.subject
                && exigir_puede_emitir(c, recorridos).is_ok()
                && firma_de_certificado_valida(&actual, c).is_ok()
        }) else {
            break;
        };
        exigir_vigencia(padre, instante_utc)?;
        actual = padre.clone();
    }

    bail!(
        "el certificado del sello no encadena con ninguna de las anclas aportadas: \
         la fecha no viene de una autoridad en la que hayas dicho confiar"
    )
}

/// ¿Este certificado está autorizado a EMITIR otros?
///
/// Sin esta comprobación, el anclaje se conformaba con que el nombre del emisor
/// cuadrara y la firma verificara — y eso convierte en autoridad certificadora a
/// cualquier certificado de entidad final. Quien tuviera un certificado TLS
/// cualquiera emitido bajo la misma raíz que el verificador aporta en `--tsa-ca`
/// podía firmar con él una hoja falsa con el uso de sellado y obtener un anclaje
/// válido: fecha inventada, atribuida a una autoridad real. Es el fallo clásico de
/// validación de rutas, y lo tenía esta función hasta que la revisión lo cazó.
///
/// Se exige, sobre `basicConstraints` (RFC 5280 §4.2.1.9):
///   - que la extensión ESTÉ y diga `cA = TRUE`. Ausente es rechazo, nunca un
///     permiso por defecto.
///   - `pathLenConstraint`, si viene, contra los certificados ya recorridos.
///
/// Y sobre `keyUsage` (§4.2.1.3): si está presente, que afirme `keyCertSign`. Si
/// no está, no se inventa: la norma la hace obligatoria para una CA, pero su
/// ausencia ya la cubre el rechazo por `basicConstraints`.
fn exigir_puede_emitir(cert: &Certificate, recorridos: usize) -> Result<()> {
    let Some(bytes) = extension(cert, &OID_EXT_BASIC_CONSTRAINTS) else {
        bail!(
            "«{}» no declara basicConstraints, así que no es una autoridad \
             certificadora y no puede avalar a nadie",
            cert.tbs_certificate.subject
        );
    };
    let bc = x509_cert::ext::pkix::BasicConstraints::from_der(bytes)
        .context("el basicConstraints del certificado no se pudo leer")?;
    if !bc.ca {
        bail!(
            "«{}» tiene basicConstraints con cA = FALSE: es un certificado de \
             entidad final y no puede emitir otros",
            cert.tbs_certificate.subject
        );
    }
    if bc.path_len_constraint.is_some_and(|m| recorridos > m as usize) {
        bail!(
            "«{}» limita la ruta a {} y ya se han recorrido {recorridos} certificados",
            cert.tbs_certificate.subject,
            bc.path_len_constraint.unwrap_or(0)
        );
    }
    if let Some(ku) = extension(cert, &OID_EXT_KEY_USAGE) {
        let usos = x509_cert::ext::pkix::KeyUsage::from_der(ku)
            .context("el keyUsage del certificado no se pudo leer")?;
        if !usos.key_cert_sign() {
            bail!(
                "«{}» tiene keyUsage sin keyCertSign: su clave no está autorizada a \
                 firmar certificados",
                cert.tbs_certificate.subject
            );
        }
    }
    Ok(())
}

/// Verifica la firma de un certificado con la clave pública de su emisor.
fn firma_de_certificado_valida(cert: &Certificate, emisor: &Certificate) -> Result<()> {
    let tbs = cert
        .tbs_certificate
        .to_der()
        .context("no se pudo recodificar el certificado para verificar su firma")?;
    verificar_firma_sobre(
        emisor,
        &cert.signature_algorithm.oid,
        // Con rsaEncryption en un certificado no hay `digest_alg` aparte; SHA-256
        // es el único caso en que esto se consulta y viene ya resuelto arriba.
        &OID_SHA256,
        &tbs,
        cert.signature.raw_bytes(),
    )
}

/// Lee anclas de confianza de un PEM con uno o más certificados.
pub fn anclas_desde_pem(pem: &str) -> Result<Vec<Certificate>> {
    let mut salida = Vec::new();
    for bloque in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let Some(cuerpo) = bloque.split("-----END CERTIFICATE-----").next() else {
            bail!("el PEM de anclas tiene un bloque BEGIN sin su END");
        };
        let limpio: String = cuerpo.chars().filter(|c| !c.is_whitespace()).collect();
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(limpio.as_bytes())
            .context("un certificado del PEM de anclas no es base64 válido")?;
        salida.push(
            Certificate::from_der(&der).context("un certificado del PEM de anclas no es DER válido")?,
        );
    }
    if salida.is_empty() {
        bail!("el archivo de anclas no contiene ningún certificado PEM");
    }
    Ok(salida)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Los tres certificados del token real: hoja, intermedia y raíz de DigiCert.
    /// Se usan porque son datos de verdad — la hoja es `CA:FALSE` con `keyUsage`
    /// solo de firma digital, la intermedia `CA:TRUE, pathlen:0`, la raíz
    /// `CA:TRUE` — y una regla de rutas hay que probarla contra jerarquías reales.
    fn certificados() -> Vec<Certificate> {
        use cms::cert::CertificateChoices;
        const TOKEN: &[u8] =
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fijos/sello_digicert.tsr"));
        let ci = ContentInfo::from_der(TOKEN).unwrap();
        let sd: SignedData = ci.content.decode_as().unwrap();
        sd.certificates
            .unwrap()
            .0
            .iter()
            .filter_map(|c| match c {
                CertificateChoices::Certificate(c) => Some(c.clone()),
                _ => None,
            })
            .collect()
    }

    fn por_nombre(trozo: &str) -> Certificate {
        certificados()
            .into_iter()
            .find(|c| c.tbs_certificate.subject.to_string().contains(trozo))
            .unwrap_or_else(|| panic!("el token debe traer «{trozo}»"))
    }

    #[test]
    fn una_hoja_no_puede_emitir_certificados() {
        // ESTE es el agujero que la revisión encontró: sin esta comprobación,
        // cualquiera con un certificado de entidad final bajo la misma raíz que el
        // verificador aporta podía firmar con él una hoja falsa de sellado y
        // obtener un anclaje válido. Fecha inventada, atribuida a DigiCert.
        let hoja = por_nombre("Timestamp Responder");
        let e = exigir_puede_emitir(&hoja, 0).unwrap_err();
        assert!(
            e.to_string().contains("cA = FALSE"),
            "debe rechazarse por basicConstraints: {e}"
        );
    }

    #[test]
    fn una_intermedia_y_una_raiz_si_pueden() {
        // El control de la prueba anterior: si rechazara también a estas, no
        // estaría discriminando, estaría rompiendo el anclaje legítimo.
        exigir_puede_emitir(&por_nombre("TimeStamping RSA4096"), 0).unwrap();
        exigir_puede_emitir(&por_nombre("Trusted Root G4"), 1).unwrap();
    }

    #[test]
    fn pathlen_cero_no_admite_una_ca_por_debajo() {
        // La intermedia de DigiCert lleva `pathlen:0`: puede emitir hojas, no
        // otras autoridades. Con un certificado ya recorrido, deja de valer.
        let intermedia = por_nombre("TimeStamping RSA4096");
        let e = exigir_puede_emitir(&intermedia, 1).unwrap_err();
        assert!(e.to_string().contains("limita la ruta"), "{e}");
    }

    #[test]
    fn sin_basic_constraints_se_rechaza_en_vez_de_suponer() {
        // Un certificado sin la extensión no es «probablemente una CA»: no lo es.
        // Se construye quitándole las extensiones a la raíz, que sí las tiene.
        let mut raiz = por_nombre("Trusted Root G4");
        raiz.tbs_certificate.extensions = None;
        let e = exigir_puede_emitir(&raiz, 0).unwrap_err();
        assert!(e.to_string().contains("no declara basicConstraints"), "{e}");
    }
}

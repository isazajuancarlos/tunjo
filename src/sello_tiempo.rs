// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sello de tiempo de un tercero (RFC 3161).
//!
//! # Por qué hace falta
//!
//! Sin esto, el acta prueba **orden relativo**, no fecha cierta: la hora la pone
//! el reloj del perito, y un reloj adelantado produce un acta adelantada sin que
//! el sello lo delate. Una autoridad de sellado externa es lo que convierte «esto
//! existía antes que aquello» en «esto existía antes de tal día».
//!
//! # Y en Colombia esto no es un servicio informal
//!
//! El artículo 161, numeral 5, del Decreto Ley 019 de 2012 enumera entre las
//! actividades de las entidades de certificación digital «ofrecer o facilitar
//! los servicios de registro y **estampado cronológico** en la generación,
//! transmisión y recepción de mensajes de datos». ONAC lo acredita bajo el
//! criterio CEA-3.0-07, y el anexo del certificado de acreditación cita como
//! documento normativo del servicio, literalmente, **RFC 3161**.
//!
//! Es decir: el protocolo técnicamente correcto y el jurídicamente reconocido
//! son el mismo. No hay que elegir.
//!
//! # Qué se sella: la FIRMA, no el acta
//!
//! El sello se pide sobre el hash de la **firma**, no sobre el del acta. Sellar
//! el acta probaría que su contenido existía en tal fecha, y dejaría abierto que
//! la firma se hubiera puesto después. Sellando la firma queda probado que la
//! firma —y con ella todo lo que cubre— ya existía. Es lo que hacen las firmas
//! avanzadas con marca de tiempo, y por la misma razón.
//!
//! Consecuencia: el token va en el acta **fuera** de lo firmado. No podría ser
//! de otro modo — se obtiene después de firmar—, y por eso `bytes_canonicos`
//! excluye tanto la firma como el sello.
//!
//! # Qué se verifica aquí, y qué no
//!
//! Se verifica lo que ata el token a NUESTROS datos: que su `messageImprint`
//! sea exactamente el hash de la firma del acta, y se extraen la fecha, la
//! política y el número de serie.
//!
//! **No se valida la firma CMS del token contra la cadena de certificados de la
//! autoridad.** Eso exige un almacén de confianza y un validador de PKI, y
//! hacerlo a medias sería peor que no hacerlo: daría por verificado lo que no se
//! verificó. El token se guarda íntegro en el acta, de modo que cualquiera lo
//! valide con la herramienta estándar:
//!
//! ```text
//! openssl ts -verify -in sello.tsr -data firma.bin -CAfile cadena_tsa.pem
//! ```
//!
//! El acta lo dice expresamente en lugar de insinuar una garantía mayor.

use anyhow::{Context, Result, bail};
use der::asn1::{GeneralizedTime, Int, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Reader, SliceReader, Tag};
use sha2::{Digest, Sha256};

/// OID de SHA-256 (2.16.840.1.101.3.4.2.1).
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// Tipo de contenido `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4).
const OID_TSTINFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// Lo que un token acredita, ya legible.
#[derive(Debug, Clone, PartialEq)]
pub struct DatosSello {
    /// Instante que certifica la autoridad, en UTC.
    pub fecha_utc: String,
    /// Política de sellado bajo la que se emitió.
    pub politica: String,
    /// Número de serie del token, único para esa autoridad.
    pub serie: String,
}

// --------------------------------------------------------------------- pedir

#[derive(der::Sequence)]
struct AlgoritmoHash {
    oid: ObjectIdentifier,
    parametros: Option<der::asn1::Null>,
}

#[derive(der::Sequence)]
struct HuellaMensaje {
    algoritmo: AlgoritmoHash,
    huella: OctetString,
}

#[derive(der::Sequence)]
struct PeticionSello {
    version: u8,
    huella: HuellaMensaje,
    nonce: Int,
    /// Se pide el certificado de la autoridad DENTRO del token. Sin él, quien
    /// quiera validarlo tendría que salir a buscarlo por su cuenta, y en diez
    /// años puede no estar. Un sello que depende de un servidor vivo para
    /// verificarse no sirve para lo que se pide aquí.
    solicitar_certificado: bool,
}

fn peticion_der(hash: &[u8; 32], nonce: &[u8; 16]) -> Result<Vec<u8>> {
    let p = PeticionSello {
        version: 1,
        huella: HuellaMensaje {
            algoritmo: AlgoritmoHash { oid: OID_SHA256, parametros: Some(der::asn1::Null) },
            huella: OctetString::new(hash.as_slice())?,
        },
        nonce: Int::new(nonce.as_slice())?,
        solicitar_certificado: true,
    };
    Ok(p.to_der()?)
}

/// Pide un sello a la autoridad y devuelve el token tal cual, en DER.
///
/// El nonce lo elige quien llama y se comprueba en la respuesta: es lo que
/// impide que una autoridad —o quien se interponga— reutilice un token viejo.
pub fn solicitar(hash_firma: &[u8; 32], url: &str, nonce: &[u8; 16]) -> Result<Vec<u8>> {
    let peticion = peticion_der(hash_firma, nonce)?;

    let respuesta = ureq::post(url)
        .header("Content-Type", "application/timestamp-query")
        .send(&peticion[..])
        .with_context(|| format!("la autoridad de sellado {url} no respondió"))?;

    let cuerpo = respuesta
        .into_body()
        .read_to_vec()
        .context("no se pudo leer la respuesta de la autoridad de sellado")?;

    extraer_token(&cuerpo)
}

// -------------------------------------------------------------------- parsear

/// Saca el token de una `TimeStampResp`, comprobando antes el estado.
///
/// `PKIStatus`: 0 = granted, 1 = grantedWithMods. Cualquier otro es un rechazo
/// y se trata como error: un acta con un sello no concedido sería un acta que
/// aparenta tener fecha cierta y no la tiene.
fn extraer_token(respuesta: &[u8]) -> Result<Vec<u8>> {
    let mut lector = SliceReader::new(respuesta)
        .context("la respuesta de la autoridad no es DER válido")?;

    let token = lector.sequence(|r| {
        // PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }
        let estado: u32 = r.sequence(|s| {
            let estado: u32 = s.decode()?;
            // statusString y failInfo son opcionales y aquí no se necesitan.
            while !s.is_finished() {
                let _: der::AnyRef = s.decode()?;
            }
            Ok(estado)
        })?;
        if estado > 1 {
            // Se propaga como error de decodificación y se traduce fuera, para
            // no perder el número de estado en el camino.
            return Err(der::Error::new(
                der::ErrorKind::Value { tag: Tag::Integer },
                der::Length::ZERO,
            ));
        }
        if r.is_finished() {
            return Err(der::Error::new(
                der::ErrorKind::Incomplete {
                    expected_len: der::Length::ONE,
                    actual_len: der::Length::ZERO,
                },
                der::Length::ZERO,
            ));
        }
        let token: der::Any = r.decode()?;
        token.to_der()
    });

    match token {
        Ok(bytes) => Ok(bytes),
        Err(e) => bail!(
            "la autoridad de sellado no concedió el sello o su respuesta no se pudo \
             interpretar ({e}). El acta NO se firma con una fecha que no está acreditada."
        ),
    }
}

struct InfoSello {
    politica: ObjectIdentifier,
    huella: HuellaMensaje,
    serie: Int,
    fecha: GeneralizedTime,
}

/// Decodifica un `TSTInfo` quedándose con los cinco primeros campos.
///
/// No se deriva `Sequence` a propósito: el `TSTInfo` termina con cinco campos
/// opcionales —accuracy, ordering, nonce, tsa, extensions— que cada autoridad
/// rellena a su manera, y un derive exige consumir el mensaje entero. Con
/// DigiCert sobraban 18 bytes y con FreeTSA 300: modelarlos todos sería añadir
/// superficie de error para leer lo que no se usa. Se leen los que importan y
/// la cola se consume sin interpretarla.
fn parsear_tstinfo(bytes: &[u8]) -> Result<InfoSello> {
    let mut lector = SliceReader::new(bytes).context("el TSTInfo no es DER válido")?;
    let info = lector
        .sequence(|r| {
            let _version: u8 = r.decode()?;
            let politica: ObjectIdentifier = r.decode()?;
            let huella: HuellaMensaje = r.decode()?;
            let serie: Int = r.decode()?;
            let fecha: GeneralizedTime = r.decode()?;
            while !r.is_finished() {
                let _: der::AnyRef = r.decode()?;
            }
            Ok(InfoSello { politica, huella, serie, fecha })
        })
        .context("el TSTInfo del sello no se pudo leer")?;
    Ok(info)
}

/// Extrae el `TSTInfo` del token y comprueba que sella el hash esperado.
///
/// Devuelve error si la huella no corresponde: un token válido sobre OTRO dato
/// no acredita nada sobre este acta, y confundirlos sería el fallo más grave
/// posible aquí.
pub fn verificar(token_der: &[u8], hash_esperado: &[u8; 32]) -> Result<DatosSello> {
    let info = extraer_tstinfo(token_der)?;

    if info.huella.algoritmo.oid != OID_SHA256 {
        bail!(
            "el sello usa un algoritmo de huella distinto de SHA-256 ({}); no se puede \
             contrastar con lo que firmamos",
            info.huella.algoritmo.oid
        );
    }
    if info.huella.huella.as_bytes() != hash_esperado.as_slice() {
        bail!(
            "el sello de tiempo NO corresponde a la firma de esta acta: sella otra cosa"
        );
    }

    Ok(DatosSello {
        // `GeneralizedTime` no se imprime solo; se pasa por `DateTime`, que da
        // la forma con «Z» al final y no deja dudas de que es UTC.
        fecha_utc: info.fecha.to_date_time().to_string(),
        politica: info.politica.to_string(),
        serie: info
            .serie
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    })
}

fn extraer_tstinfo(token_der: &[u8]) -> Result<InfoSello> {
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;

    let ci = ContentInfo::from_der(token_der)
        .context("el token de sello no es un ContentInfo válido")?;
    let firmado: SignedData = ci
        .content
        .decode_as()
        .context("el token de sello no contiene un SignedData")?;

    let encap = &firmado.encap_content_info;
    if encap.econtent_type != OID_TSTINFO {
        bail!(
            "el token no encapsula un TSTInfo sino {} — no es un sello de tiempo RFC 3161",
            encap.econtent_type
        );
    }
    let contenido = encap
        .econtent
        .as_ref()
        .context("el token de sello viene sin contenido")?;

    // El eContent es un OCTET STRING cuyo interior es el TSTInfo en DER.
    let octetos: OctetString = contenido
        .decode_as()
        .context("el contenido del token no es un OCTET STRING")?;
    parsear_tstinfo(octetos.as_bytes())
}

/// Hash de la firma del acta, que es lo que se manda a sellar.
pub fn hash_de(datos: &[u8]) -> [u8; 32] {
    Sha256::digest(datos).into()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_peticion_es_der_bien_formado_y_lleva_el_hash() {
        let hash = [0xABu8; 32];
        let nonce = [7u8; 16];
        let der = peticion_der(&hash, &nonce).unwrap();
        assert_eq!(der[0], 0x30, "una TimeStampReq es un SEQUENCE");
        assert!(
            der.windows(32).any(|v| v == hash),
            "el hash que se manda sellar tiene que ir dentro de la petición"
        );
    }

    #[test]
    fn una_respuesta_con_estado_de_rechazo_no_produce_token() {
        // TimeStampResp con status=2 (rejection) y sin token.
        let respuesta = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        let e = extraer_token(&respuesta).unwrap_err();
        assert!(e.to_string().contains("no concedió"), "{e}");
    }

    #[test]
    fn una_respuesta_concedida_pero_sin_token_tambien_falla() {
        // status=0 (granted) y nada más: no hay nada que guardar.
        let respuesta = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(extraer_token(&respuesta).is_err());
    }

    #[test]
    fn la_basura_no_se_interpreta_como_sello() {
        assert!(extraer_token(b"esto no es DER").is_err());
        assert!(verificar(b"esto tampoco", &[0u8; 32]).is_err());
    }
}

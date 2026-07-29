// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cadena de custodia: la secuencia de eventos sobre una evidencia ya sellada.
//!
//! Un acta (`acta.json`) prueba un INSTANTE: «esto existía en T0, con esta raíz
//! Merkle, firmado». Pero *cadena de custodia* significa la secuencia
//! ININTERRUMPIDA de quién la tuvo y qué hizo: recogida, transferencia,
//! análisis, almacenamiento, presentación. Este módulo la lleva como una
//! bitácora **encadenada por hash y firmada** (sobre `guaca::auditoria`): cada
//! evento apunta al anterior, así que **borrar o reordenar rompe la cadena**, no
//! solo alterar.
//!
//! Va firmada en **TRIPLE** (Ed25519 + ML-DSA-87 + SLH-DSA), el mismo nivel que
//! el acta: la custodia no puede ser el eslabón criptográficamente débil de una
//! prueba que aguanta décadas.
//!
//! El acta NO se toca: la cadena es un artefacto aparte (`cadena.json`) anclado
//! al acta por el SHA-256 de sus bytes canónicos. Las actas ya selladas siguen
//! verificando idénticas.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use guaca::auditoria::{self, Auditoria, Entrada, GENESIS};
use quipu::pqsign::{TripleSigningKey, TripleVerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Marca de formato de la cadena. Va DENTRO del archivo para que un lector futuro
/// sepa qué está leyendo y con qué reglas verificarlo.
pub const FORMATO_CADENA: &str = "tunjo-cadena-custodia-v1";

/// Un evento de custodia: el contenido que el perito declara. Es lo que se firma
/// (junto con su posición en la cadena), así que cambiar cualquier campo rompe
/// la firma de ese eslabón.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Evento {
    /// `adquisicion`, `transferencia`, `analisis`, `almacenamiento`,
    /// `presentacion` u otro que el caso exija.
    pub tipo: String,
    /// Quién ejecuta el evento (y, en una transferencia, quién recibe va en la
    /// descripción o en un evento siguiente de quien recibe).
    pub actor: String,
    /// Documento del actor.
    pub identificacion: String,
    /// `perito`, `custodio`, `receptor`, `analista`…
    pub rol: String,
    /// Momento del evento en UTC (RFC 3339).
    pub fecha_utc: String,
    /// Cómo se contrastó el reloj, o `NO VERIFICADO`. Nunca se rellena con un
    /// supuesto: el mismo principio que el acta.
    pub reloj: String,
    /// Qué ocurrió, en palabras.
    pub descripcion: String,
}

/// Un eslabón ya sellado: el evento más su envoltura criptográfica.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Eslabon {
    pub secuencia: u64,
    /// Hash (hex) del eslabón anterior; en el génesis, 64 ceros.
    pub hash_anterior: String,
    pub evento: Evento,
    /// Hash (hex) de este eslabón: cubre secuencia + hash_anterior + evento.
    pub hash: String,
    /// Firma triple desprendida (base64) sobre la misma preimagen.
    pub firma: String,
}

/// La cadena entera, anclada a un acta.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Cadena {
    pub formato: String,
    /// Ancla: SHA-256 (hex) de los bytes canónicos del acta. El génesis lo lleva
    /// firmado, así que cambiarlo aquí sin re-firmar rompe la cadena.
    pub acta_sha256: String,
    /// Clave pública triple (base64) del perito. Quien verifica la usa; no hace
    /// falta pedir nada a quien emitió.
    pub clave_publica: String,
    pub eslabones: Vec<Eslabon>,
}

/// La referencia al acta contra la que se contrasta una cadena: sus bytes
/// canónicos (para el ancla) y la clave pública del perito que la firmó. Ambas
/// hacen falta: el ancla ata la cadena al CONTENIDO del acta, y la clave la ata
/// a su AUTOR —sin lo segundo, cualquiera fabrica una cadena con su propia clave
/// que «corresponde» a un acta ajena—.
pub struct Ancla<'a> {
    pub bytes_canonicos: &'a [u8],
    pub clave_publica: &'a str,
}

/// Veredicto de verificar una cadena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// La cadena es íntegra y —si se dio el acta— le corresponde y la firmó su
    /// mismo perito.
    Intacta,
    /// La PRIMERA ruptura hallada.
    Rota { secuencia: u64, motivo: String },
    /// La cadena es íntegra pero ancla OTRA acta que la entregada.
    ActaNoCorresponde { esperado: String, encontrado: String },
    /// La cadena es íntegra pero la firmó una clave que NO es la del perito del
    /// acta: no la levantó quien selló la evidencia.
    FirmanteAjeno { esperado: String, encontrado: String },
    /// La cadena no arranca en el eslabón 0: está vacía, o su primer eslabón lleva
    /// otra secuencia. Sin génesis no atestigua ninguna custodia —falte el
    /// principio o falte entera—, así que no puede declararse íntegra.
    SinGenesis,
}

fn a_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn de_hex32(s: &str) -> Option<[u8; 32]> {
    // `!s.is_ascii()` evita el panic de indexar un &str a mitad de un carácter
    // UTF-8 multibyte: un hash de una cadena.json manipulada no debe tumbar la
    // verificación, sino rechazarse.
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    a_hex(&h.finalize())
}

/// El contenido canónico que se hashea y firma para un eslabón. En el génesis
/// (`ancla` = `Some`) incluye el ancla del acta, así que queda FIRMADA. Es la
/// única fuente de este mapa: sellar y verificar la llaman igual, o no cuadraría.
fn contenido_de(evento: &Evento, ancla: Option<&str>) -> BTreeMap<String, Value> {
    let mut m = BTreeMap::new();
    m.insert("v".into(), Value::from(1));
    m.insert("tipo".into(), Value::from(evento.tipo.clone()));
    m.insert("actor".into(), Value::from(evento.actor.clone()));
    m.insert("identificacion".into(), Value::from(evento.identificacion.clone()));
    m.insert("rol".into(), Value::from(evento.rol.clone()));
    m.insert("fecha_utc".into(), Value::from(evento.fecha_utc.clone()));
    m.insert("reloj".into(), Value::from(evento.reloj.clone()));
    m.insert("descripcion".into(), Value::from(evento.descripcion.clone()));
    if let Some(a) = ancla {
        m.insert("ancla_acta_sha256".into(), Value::from(a));
    }
    m
}

/// Cierra el firmante triple sobre la clave privada del perito.
fn firmante(sk: &TripleSigningKey) -> impl Fn(&[u8]) -> Option<String> + '_ {
    move |pre: &[u8]| Some(STANDARD.encode(sk.sign(pre)))
}

/// Inicia una cadena sobre un acta ya sellada. El evento génesis (normalmente la
/// adquisición) ancla el SHA-256 de los bytes canónicos del acta.
pub fn iniciar(acta_bytes_canonicos: &[u8], adquisicion: Evento, sk: &TripleSigningKey) -> Cadena {
    let ancla = sha256_hex(acta_bytes_canonicos);
    let cont = contenido_de(&adquisicion, Some(&ancla));
    let sello = auditoria::sellar_con(0, GENESIS, &cont, firmante(sk))
        .expect("una clave triple recién cargada siempre firma");
    Cadena {
        formato: FORMATO_CADENA.to_string(),
        acta_sha256: ancla,
        clave_publica: STANDARD.encode(sk.verifying_key().to_bytes()),
        eslabones: vec![Eslabon {
            secuencia: 0,
            hash_anterior: a_hex(&GENESIS),
            evento: adquisicion,
            hash: a_hex(&sello.hash),
            firma: sello.firma,
        }],
    }
}

/// Añade un eslabón a la cadena, encadenado al último y firmado en triple.
pub fn agregar(cadena: &mut Cadena, evento: Evento, sk: &TripleSigningKey) -> Result<()> {
    let ultimo = cadena
        .eslabones
        .last()
        .ok_or_else(|| anyhow!("la cadena no tiene ni génesis: usa iniciar()"))?;
    let secuencia = ultimo.secuencia + 1;
    let anterior = de_hex32(&ultimo.hash)
        .ok_or_else(|| anyhow!("el hash del último eslabón está corrupto"))?;
    let hash_anterior_hex = ultimo.hash.clone();

    let cont = contenido_de(&evento, None);
    let sello = auditoria::sellar_con(secuencia, anterior, &cont, firmante(sk))
        .expect("una clave triple válida siempre firma");
    cadena.eslabones.push(Eslabon {
        secuencia,
        hash_anterior: hash_anterior_hex,
        evento,
        hash: a_hex(&sello.hash),
        firma: sello.firma,
    });
    Ok(())
}

/// Verifica la cadena entera: que arranque en el génesis, y luego eslabones,
/// hashes, firmas triple y contigüidad. Si se pasa el [`Ancla`] del acta,
/// comprueba además que (a) la firmó el MISMO perito que el acta y (b) ancla
/// ese acta —por autor y por contenido, respectivamente—. Falla
/// ruidosamente si la clave pública o algún hash no son válidos: una cadena que
/// no se puede ni leer no es una cadena.
pub fn verificar(cadena: &Cadena, acta: Option<Ancla>) -> Result<Veredicto> {
    let vk_bytes = STANDARD
        .decode(&cadena.clave_publica)
        .map_err(|_| anyhow!("la clave pública de la cadena no es base64 válido"))?;
    let vk = TripleVerifyingKey::from_bytes(&vk_bytes)
        .ok_or_else(|| anyhow!("la clave pública de la cadena no es una clave triple válida"))?;

    let mut entradas = Vec::with_capacity(cadena.eslabones.len());
    for esl in &cadena.eslabones {
        let ancla = (esl.secuencia == 0).then_some(cadena.acta_sha256.as_str());
        entradas.push(Entrada {
            secuencia: esl.secuencia,
            hash_anterior: de_hex32(&esl.hash_anterior)
                .ok_or_else(|| anyhow!("hash_anterior corrupto en el eslabón {}", esl.secuencia))?,
            contenido: contenido_de(&esl.evento, ancla),
            hash: de_hex32(&esl.hash)
                .ok_or_else(|| anyhow!("hash corrupto en el eslabón {}", esl.secuencia))?,
            firma: esl.firma.clone(),
        });
    }

    let verif = |pre: &[u8], tok: &str| {
        STANDARD.decode(tok).map(|s| vk.verify(pre, &s)).unwrap_or(false)
    };
    if let Auditoria::Rota { secuencia, motivo } = auditoria::verificar_con(&entradas, verif) {
        return Ok(Veredicto::Rota { secuencia, motivo: format!("{motivo:?}") });
    }

    // Los eslabones se encadenan bien ENTRE SÍ. Pero `verificar_con` solo exige la
    // contigüidad a partir del SEGUNDO: al primero solo le pide `hash_anterior ==
    // GENESIS`, no que su secuencia sea 0. Una cadena fabricada que arranque en
    // `seq=5` le cuadra entera. Ese arranque se exige aquí, SIEMPRE —con acta o
    // sin ella—: sin génesis no hay «sin saltos» que declarar, y `acta_sha256`
    // queda como un campo suelto que nadie firmó.
    if !cadena.eslabones.first().is_some_and(|e| e.secuencia == 0) {
        return Ok(Veredicto::SinGenesis);
    }

    // La cadena es íntegra. Si se pide contrastar contra un acta, hay que atarla
    // a ese acta por CONTENIDO y por AUTOR.
    if let Some(ancla) = acta {
        // (a) Autor: el firmante de la cadena tiene que ser el perito del acta.
        //     Sin esto, cualquiera fabrica una cadena con SU clave anclada a un
        //     acta ajena y «corresponde».
        if cadena.clave_publica != ancla.clave_publica {
            return Ok(Veredicto::FirmanteAjeno {
                esperado: ancla.clave_publica.to_string(),
                encontrado: cadena.clave_publica.clone(),
            });
        }
        // (b) Contenido: el ancla firmada en el génesis es el hash de este acta.
        //     (Si `acta_sha256` estuviera falseada, el génesis ya habría roto.)
        let esperado = sha256_hex(ancla.bytes_canonicos);
        if esperado != cadena.acta_sha256 {
            return Ok(Veredicto::ActaNoCorresponde {
                esperado,
                encontrado: cadena.acta_sha256.clone(),
            });
        }
    }
    Ok(Veredicto::Intacta)
}

/// Lee una cadena desde JSON, rechazando un formato desconocido.
pub fn desde_json(texto: &str) -> Result<Cadena> {
    let cadena: Cadena = serde_json::from_str(texto).map_err(|e| anyhow!("cadena inválida: {e}"))?;
    if cadena.formato != FORMATO_CADENA {
        bail!("formato de cadena desconocido: {:?}", cadena.formato);
    }
    Ok(cadena)
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use quipu::pqsign::generate_triple_keypair;

    fn evento(tipo: &str, actor: &str) -> Evento {
        Evento {
            tipo: tipo.into(),
            actor: actor.into(),
            identificacion: "CC 123".into(),
            rol: "perito".into(),
            fecha_utc: "2026-07-29T15:00:00Z".into(),
            reloj: "NO VERIFICADO".into(),
            descripcion: format!("evento {tipo}"),
        }
    }

    fn cadena_de_tres(acta: &[u8]) -> (Cadena, TripleSigningKey) {
        let (_, sk) = generate_triple_keypair();
        let mut c = iniciar(acta, evento("adquisicion", "perito"), &sk);
        agregar(&mut c, evento("transferencia", "receptor"), &sk).unwrap();
        agregar(&mut c, evento("analisis", "analista"), &sk).unwrap();
        (c, sk)
    }

    /// El ancla del acta cuando el firmante de la cadena ES el perito (caso
    /// legítimo): misma clave que firmó la cadena.
    fn ancla_propia<'a>(c: &'a Cadena, acta: &'a [u8]) -> Ancla<'a> {
        Ancla { bytes_canonicos: acta, clave_publica: &c.clave_publica }
    }

    #[test]
    fn una_cadena_bien_formada_verifica_y_corresponde_al_acta() {
        let acta = b"bytes canonicos del acta";
        let (c, _) = cadena_de_tres(acta);
        assert_eq!(c.eslabones.len(), 3);
        assert_eq!(verificar(&c, Some(ancla_propia(&c, acta))).unwrap(), Veredicto::Intacta);
        assert_eq!(verificar(&c, None).unwrap(), Veredicto::Intacta);
    }

    #[test]
    fn alterar_un_evento_rompe_el_hash() {
        let acta = b"bytes canonicos del acta";
        let (mut c, _) = cadena_de_tres(acta);
        c.eslabones[1].evento.descripcion = "lo entregué a otro, en realidad".into();
        assert!(matches!(
            verificar(&c, Some(ancla_propia(&c, acta))).unwrap(),
            Veredicto::Rota { secuencia: 1, .. }
        ));
    }

    #[test]
    fn borrar_un_eslabon_intermedio_se_detecta() {
        let acta = b"bytes canonicos del acta";
        let (mut c, _) = cadena_de_tres(acta);
        c.eslabones.remove(1); // desaparece la transferencia
        assert!(matches!(
            verificar(&c, Some(ancla_propia(&c, acta))).unwrap(),
            Veredicto::Rota { secuencia: 2, .. }
        ));
    }

    #[test]
    fn una_cadena_de_otra_acta_no_corresponde() {
        let (c, _) = cadena_de_tres(b"acta A");
        // Mismo perito (pasa el chequeo de autor), pero otro acta.
        let a = Ancla { bytes_canonicos: b"acta B (otra)", clave_publica: &c.clave_publica };
        match verificar(&c, Some(a)).unwrap() {
            Veredicto::ActaNoCorresponde { .. } => {}
            otro => panic!("debía ser ActaNoCorresponde, fue {otro:?}"),
        }
    }

    #[test]
    fn falsear_el_ancla_sin_re_firmar_rompe_el_genesis() {
        let acta = b"bytes canonicos del acta";
        let (mut c, _) = cadena_de_tres(acta);
        // Apuntar la cadena a otra acta editando el campo: el ancla va firmada en
        // el génesis, así que la firma/hash del eslabón 0 deja de cuadrar.
        c.acta_sha256 = sha256_hex(b"acta falsificada");
        assert!(matches!(
            verificar(&c, None).unwrap(),
            Veredicto::Rota { secuencia: 0, .. }
        ));
    }

    #[test]
    fn un_eslabon_firmado_con_otra_clave_no_verifica() {
        let acta = b"bytes canonicos del acta";
        let (mut c, _) = cadena_de_tres(acta);
        // Re-sellar el eslabón 1 con OTRA clave: hash y eslabón cuadran, la firma
        // triple no valida contra la clave pública de la cadena.
        let (_, otra_sk) = generate_triple_keypair();
        let anterior = de_hex32(&c.eslabones[1].hash_anterior).unwrap();
        let cont = contenido_de(&c.eslabones[1].evento, None);
        let re = auditoria::sellar_con(1, anterior, &cont, firmante(&otra_sk)).unwrap();
        c.eslabones[1].firma = re.firma;
        assert!(matches!(
            verificar(&c, Some(ancla_propia(&c, acta))).unwrap(),
            Veredicto::Rota { secuencia: 1, motivo } if motivo.contains("Firma")
        ));
    }

    /// Security-review Vuln 1: una cadena internamente VÁLIDA, firmada por OTRA
    /// clave y anclada al hash de un acta ajena, NO debe «corresponder» a ese
    /// acta. Antes daba Intacta; ahora la ata al autor.
    #[test]
    fn una_cadena_de_otro_firmante_no_corresponde_al_acta() {
        let acta = b"acta legitima publicada";
        let (c_ajena, _) = cadena_de_tres(acta); // firmada por una clave cualquiera
        // La clave REAL del perito del acta es otra.
        let (perito_vk, _) = generate_triple_keypair();
        let perito_pub = STANDARD.encode(perito_vk.to_bytes());
        let a = Ancla { bytes_canonicos: acta, clave_publica: &perito_pub };
        match verificar(&c_ajena, Some(a)).unwrap() {
            Veredicto::FirmanteAjeno { .. } => {}
            otro => panic!("una cadena de otro firmante debía ser FirmanteAjeno, fue {otro:?}"),
        }
    }

    /// Security-review Vuln 2: una cadena VACÍA (sin génesis) no atestigua nada;
    /// no puede «corresponder» a un acta aunque su campo acta_sha256 cuadre.
    #[test]
    fn una_cadena_vacia_no_corresponde_al_acta() {
        let acta = b"acta legitima";
        let (_, sk) = generate_triple_keypair();
        let vacia = Cadena {
            formato: FORMATO_CADENA.to_string(),
            acta_sha256: sha256_hex(acta),
            clave_publica: STANDARD.encode(sk.verifying_key().to_bytes()),
            eslabones: vec![],
        };
        let a = Ancla { bytes_canonicos: acta, clave_publica: &vacia.clave_publica };
        assert_eq!(verificar(&vacia, Some(a)).unwrap(), Veredicto::SinGenesis);
    }

    /// Ultrareview bug_004: `guaca::auditoria::verificar_con` solo exige la
    /// contigüidad A PARTIR del segundo eslabón, así que una cadena fabricada que
    /// arranca en `seq=5` con `hash_anterior = GENESIS` le cuadra entera —hashes y
    /// firmas incluidos—. El salto de GENESIS a 5 ES un salto: no puede reportarse
    /// «íntegra, sin saltos», se dé o no el acta.
    #[test]
    fn una_cadena_que_no_arranca_en_cero_no_es_integra() {
        let (_, sk) = generate_triple_keypair();
        let mut eslabones: Vec<Eslabon> = Vec::new();
        let mut anterior = GENESIS;
        for secuencia in 5..8u64 {
            let ev = evento("analisis", "quien fabrica");
            let cont = contenido_de(&ev, None);
            let sello = auditoria::sellar_con(secuencia, anterior, &cont, firmante(&sk)).unwrap();
            eslabones.push(Eslabon {
                secuencia,
                hash_anterior: a_hex(&anterior),
                evento: ev,
                hash: a_hex(&sello.hash),
                firma: sello.firma,
            });
            anterior = sello.hash;
        }
        let c = Cadena {
            formato: FORMATO_CADENA.to_string(),
            acta_sha256: sha256_hex(b"un acta cualquiera"),
            clave_publica: STANDARD.encode(sk.verifying_key().to_bytes()),
            eslabones,
        };
        assert_eq!(verificar(&c, None).unwrap(), Veredicto::SinGenesis);
    }

    /// Y una cadena vacía tampoco atestigua nada SIN acta: `verificar_con` la da
    /// por trivialmente intacta, pero cero eslabones no son una custodia.
    #[test]
    fn una_cadena_vacia_no_es_integra_ni_sin_acta() {
        let (_, sk) = generate_triple_keypair();
        let vacia = Cadena {
            formato: FORMATO_CADENA.to_string(),
            acta_sha256: sha256_hex(b"acta"),
            clave_publica: STANDARD.encode(sk.verifying_key().to_bytes()),
            eslabones: vec![],
        };
        assert_eq!(verificar(&vacia, None).unwrap(), Veredicto::SinGenesis);
    }

    /// Security-review nota: un hash con un carácter UTF-8 multibyte (de una
    /// cadena.json manipulada) se RECHAZA, no hace panic al indexar el &str.
    #[test]
    fn un_hash_no_ascii_se_rechaza_sin_panic() {
        let raro = format!("é{}", "a".repeat(62)); // 2 + 62 = 64 bytes, no ASCII
        assert_eq!(raro.len(), 64);
        assert!(de_hex32(&raro).is_none());
    }

    #[test]
    fn el_formato_desconocido_se_rechaza() {
        let acta = b"x";
        let (c, _) = cadena_de_tres(acta);
        let mut json: Value = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        json["formato"] = Value::from("otro-formato-v9");
        assert!(desde_json(&json.to_string()).is_err());
    }
}

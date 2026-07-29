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

/// Veredicto de verificar una cadena.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// La cadena es íntegra y —si se dio el acta— le corresponde.
    Intacta,
    /// La PRIMERA ruptura hallada.
    Rota { secuencia: u64, motivo: String },
    /// La cadena es íntegra pero es de OTRA acta que la entregada.
    ActaNoCorresponde { esperado: String, encontrado: String },
}

fn a_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn de_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
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

/// Verifica la cadena entera: eslabones, hashes, firmas triple y contigüidad. Si
/// se pasan los bytes canónicos del acta, comprueba además que la cadena le
/// corresponde. Falla ruidosamente si la clave pública o algún hash no son
/// válidos: una cadena que no se puede ni leer no es una cadena.
pub fn verificar(cadena: &Cadena, acta_bytes_canonicos: Option<&[u8]>) -> Result<Veredicto> {
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

    // La cadena es íntegra. ¿Es de ESTA acta? (El ancla ya va firmada en el
    // génesis, así que si estuviera falseada la comprobación de arriba habría
    // fallado; esto solo contrasta contra el acta que trae quien verifica.)
    if let Some(bytes) = acta_bytes_canonicos {
        let esperado = sha256_hex(bytes);
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

    #[test]
    fn una_cadena_bien_formada_verifica_y_corresponde_al_acta() {
        let acta = b"bytes canonicos del acta";
        let (c, _) = cadena_de_tres(acta);
        assert_eq!(c.eslabones.len(), 3);
        assert_eq!(verificar(&c, Some(acta)).unwrap(), Veredicto::Intacta);
        assert_eq!(verificar(&c, None).unwrap(), Veredicto::Intacta);
    }

    #[test]
    fn alterar_un_evento_rompe_el_hash() {
        let acta = b"bytes canonicos del acta";
        let (mut c, _) = cadena_de_tres(acta);
        c.eslabones[1].evento.descripcion = "lo entregué a otro, en realidad".into();
        assert!(matches!(
            verificar(&c, Some(acta)).unwrap(),
            Veredicto::Rota { secuencia: 1, .. }
        ));
    }

    #[test]
    fn borrar_un_eslabon_intermedio_se_detecta() {
        let acta = b"bytes canonicos del acta";
        let (mut c, _) = cadena_de_tres(acta);
        c.eslabones.remove(1); // desaparece la transferencia
        assert!(matches!(
            verificar(&c, Some(acta)).unwrap(),
            Veredicto::Rota { secuencia: 2, .. }
        ));
    }

    #[test]
    fn una_cadena_de_otra_acta_no_corresponde() {
        let (c, _) = cadena_de_tres(b"acta A");
        match verificar(&c, Some(b"acta B (otra)")).unwrap() {
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
            verificar(&c, Some(acta)).unwrap(),
            Veredicto::Rota { secuencia: 1, motivo } if motivo.contains("Firma")
        ));
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

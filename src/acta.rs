// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! El acta: qué se recogió, cómo, cuándo y quién responde por ello.
//!
//! El acta **no concluye nada**. Dice qué bytes había, con qué método se
//! leyeron y quién firma esa afirmación. Todo lo que sea interpretación —si
//! hubo intrusión, si alguien borró algo— es del dictamen del perito, no de
//! una herramienta. Una herramienta que concluye es una herramienta que se
//! derrumba en el contrainterrogatorio.

use serde::{Deserialize, Serialize};

use crate::merkle;

/// Identificador de formato. Va DENTRO de lo firmado: cambiar de versión no
/// puede pasar por reinterpretar un acta vieja con reglas nuevas.
pub const FORMATO: &str = "tunjo/acta-v1";

/// Algoritmos con los que se sella. Se escribe en el acta porque dentro de diez
/// años habrá que saber contra qué se verifica, y porque el CGP (art. 226.10)
/// exige declarar el método empleado.
pub const ALGORITMOS: &str =
    "SHA-256 (contenido y Merkle); firma 3-de-3: Ed25519 + ML-DSA-87 (FIPS 204) + SLH-DSA-SHA2-256s (FIPS 205)";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Caso {
    /// Radicado, número interno o referencia con la que el acta se cita.
    pub referencia: String,
    /// Qué se está sellando y en el marco de qué actuación.
    pub descripcion: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Perito {
    pub nombre: String,
    /// Documento de identidad o tarjeta profesional. Lo pide el CGP art. 226.
    pub identificacion: String,
    /// Clave pública triple-híbrida en base64. Es lo que permite a un tercero
    /// verificar sin pedirle nada al perito.
    pub clave_publica: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Reloj {
    /// Instante en que arrancó la adquisición, en UTC.
    pub inicio_utc: String,
    /// Instante en que terminó, en UTC.
    pub fin_utc: String,
    /// Desfase de la máquina respecto de UTC en el momento de sellar.
    pub desfase_local_utc: String,
    /// Cómo se contrastó el reloj con una fuente externa. Si el perito no lo
    /// declara, aquí queda escrito que NO se verificó — no se calla ni se
    /// rellena con un supuesto.
    pub verificacion: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Adquisicion {
    /// Ruta absoluta de la que se leyó, tal como la vio el perito.
    pub origen: String,
    /// Descripción del método: copia lógica en solo lectura, imagen previa,
    /// bloqueador de escritura empleado, etc.
    pub metodo: String,
    pub reloj: Reloj,
    pub herramienta: String,
    pub algoritmos: String,
}

/// Un elemento recogido. `estado` distingue lo leído de lo que falló: un
/// archivo ilegible se registra como tal y nunca desaparece del acta en
/// silencio.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Elemento {
    /// Ruta relativa al origen. Relativa, para que el acta se verifique aunque
    /// la copia se monte en otro punto del sistema de archivos.
    pub ruta: String,
    pub tipo: String,
    pub bytes: u64,
    /// SHA-256 en hexadecimal del contenido. Vacío si no hay contenido que
    /// hashear (directorio) o si no se pudo leer.
    pub sha256: String,
    /// Última modificación en UTC según el sistema de archivos, o vacío si el
    /// sistema no la expone. NO se sustituye por la hora actual.
    pub modificado_utc: String,
    /// `leido`, `directorio`, `enlace -> destino` o `ERROR: <motivo>`.
    pub estado: String,
    /// CÓMO se calculó `sha256`. Vacío o ausente significa el método normal:
    /// SHA-256 de los bytes del archivo.
    ///
    /// Existe porque no todo lo que se sella se verifica leyendo bytes: algo
    /// puede sellarse por una huella que se recompute con OTRA herramienta. En
    /// ese caso el acta tiene que decir cuál, porque una huella que nadie sabe
    /// repetir no sirve como prueba — y `contrastar` no puede tratarla como un
    /// archivo normal, porque recomputaría el SHA-256 de los bytes y daría
    /// ALTERADO siempre. Ante un método que no conoce, el verificador dice NO
    /// VERIFICABLE nombrándolo, en vez de mentir dando por bueno —o por
    /// alterado— lo que no comprobó.
    ///
    /// Hoy solo se emite el método normal (vacío); el campo queda para que su
    /// ausencia signifique explícitamente «bytes del archivo», no una omisión.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub metodo_huella: String,
}

/// El método de huella que se verifica leyendo los bytes del archivo.
pub const HUELLA_ARCHIVO: &str = "";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Firma {
    pub algoritmo: String,
    /// Firma en base64 sobre los bytes canónicos del acta sin este campo.
    pub valor: String,
}

/// Sello de tiempo de un tercero sobre la firma del acta.
///
/// Va aparte de la firma porque se obtiene DESPUÉS de firmar: acredita que esa
/// firma —y con ella todo lo que cubre— ya existía en la fecha que certifica la
/// autoridad. Ver `crate::sello_tiempo`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SelloTiempo {
    /// Autoridad a la que se pidió, tal como la indicó el perito.
    pub autoridad: String,
    /// Instante certificado por la autoridad, en UTC.
    pub fecha_utc: String,
    /// Política de sellado bajo la que se emitió.
    pub politica: String,
    /// Número de serie del token para esa autoridad.
    pub serie: String,
    /// El token RFC 3161 completo, en base64 y sin tocar. Es lo que permite a
    /// un tercero validarlo con `openssl ts -verify` sin depender de nosotros.
    pub token: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Acta {
    pub formato: String,
    pub caso: Caso,
    pub perito: Perito,
    pub adquisicion: Adquisicion,
    pub elementos: Vec<Elemento>,
    /// Raíz del árbol de Merkle en hexadecimal.
    pub raiz_merkle: String,
    /// `None` mientras el acta no se ha firmado.
    pub firma: Option<Firma>,
    /// `None` si no se pidió sello de tiempo. Su ausencia NO es un defecto del
    /// acta: es un límite, y el informe lo declara como tal.
    #[serde(default)]
    pub sello_tiempo: Option<SelloTiempo>,
}

/// Errores del acta. Cada uno existe porque hay una forma concreta de que un
/// acta sea inválida y valga la pena distinguirla en el informe.
#[derive(Debug, PartialEq)]
pub enum ErrorActa {
    SinElementos,
    FormatoDesconocido(String),
    SinFirma,
    FirmaMalFormada,
    ClaveMalFormada,
    RaizNoCoincide { declarada: String, calculada: String },
    FirmaInvalida,
    SelloMalFormado,
    SelloNoCorresponde(String),
}

impl std::fmt::Display for ErrorActa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SinElementos => write!(f, "el acta no tiene elementos: no hay nada que sellar"),
            Self::FormatoDesconocido(x) => write!(f, "formato de acta desconocido: {x}"),
            Self::SinFirma => write!(f, "el acta no está firmada"),
            Self::FirmaMalFormada => write!(f, "la firma no es base64 válido o no mide lo esperado"),
            Self::ClaveMalFormada => write!(f, "la clave pública del acta no es válida"),
            Self::RaizNoCoincide { declarada, calculada } => write!(
                f,
                "la raíz de Merkle declarada ({declarada}) no corresponde a los elementos del acta ({calculada})"
            ),
            Self::FirmaInvalida => write!(f, "la firma NO verifica contra la clave pública del acta"),
            Self::SelloMalFormado => write!(f, "el sello de tiempo no es base64 válido"),
            Self::SelloNoCorresponde(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ErrorActa {}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Acta {
    /// Bytes que se firman: el acta completa **sin** la firma ni el sello.
    ///
    /// El sello queda fuera por necesidad, no por comodidad: se pide sobre el
    /// hash de la firma, así que no puede existir antes de firmar. Incluirlo
    /// haría el acta imposible de firmar y de verificar.
    ///
    /// Determinista porque `serde_json` respeta el orden de declaración de los
    /// campos de una `struct` y aquí no hay ningún mapa desordenado. Esa
    /// propiedad es la que permite verificar el acta dentro de diez años, así
    /// que está cubierta por una prueba.
    pub fn bytes_canonicos(&self) -> Vec<u8> {
        let mut desnuda = self.clone();
        desnuda.firma = None;
        desnuda.sello_tiempo = None;
        serde_json::to_vec(&desnuda).expect("el acta siempre serializa")
    }

    /// Comprueba el sello de tiempo, si lo hay.
    ///
    /// `Ok(None)` significa que el acta no lleva sello — que es un límite
    /// declarado, no un error. `Err` significa que lleva uno que no cuadra, y
    /// eso sí es grave: un sello que no corresponde a esta firma no acredita
    /// nada sobre esta acta.
    pub fn verificar_sello_tiempo(&self) -> Result<Option<crate::sello_tiempo::DatosSello>, ErrorActa> {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let Some(sello) = &self.sello_tiempo else {
            return Ok(None);
        };
        let firma = self.firma.as_ref().ok_or(ErrorActa::SinFirma)?;
        let firma_bytes = STANDARD.decode(&firma.valor).map_err(|_| ErrorActa::FirmaMalFormada)?;
        let token = STANDARD.decode(&sello.token).map_err(|_| ErrorActa::SelloMalFormado)?;

        let hash = crate::sello_tiempo::hash_de(&firma_bytes);
        crate::sello_tiempo::verificar(&token, &hash)
            .map(Some)
            .map_err(|e| ErrorActa::SelloNoCorresponde(e.to_string()))
    }

    /// Raíz de Merkle calculada a partir de los elementos presentes.
    pub fn raiz_calculada(&self) -> Option<String> {
        let hojas: Vec<[u8; 32]> = self
            .elementos
            .iter()
            .map(|e| merkle::hoja(&serde_json::to_vec(e).expect("elemento serializable")))
            .collect();
        merkle::raiz(&hojas).map(|r| hex(&r))
    }

    /// Recalcula y fija la raíz. Se llama antes de firmar.
    pub fn fijar_raiz(&mut self) -> Result<(), ErrorActa> {
        self.raiz_merkle = self.raiz_calculada().ok_or(ErrorActa::SinElementos)?;
        Ok(())
    }

    /// Verificación **completa**: formato, raíz y firma.
    ///
    /// El orden importa. Verificar solo la firma dejaría pasar un acta cuya
    /// raíz no corresponde a sus elementos: la firma cubre el JSON entero,
    /// incluida una raíz mentirosa, y sin recalcularla el sello certificaría
    /// una lista que nadie comprobó.
    pub fn verificar_sello(&self) -> Result<(), ErrorActa> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use quipu::pqsign::TripleVerifyingKey;

        if self.formato != FORMATO {
            return Err(ErrorActa::FormatoDesconocido(self.formato.clone()));
        }
        let calculada = self.raiz_calculada().ok_or(ErrorActa::SinElementos)?;
        if calculada != self.raiz_merkle {
            return Err(ErrorActa::RaizNoCoincide {
                declarada: self.raiz_merkle.clone(),
                calculada,
            });
        }
        let firma = self.firma.as_ref().ok_or(ErrorActa::SinFirma)?;
        let sig = STANDARD
            .decode(&firma.valor)
            .map_err(|_| ErrorActa::FirmaMalFormada)?;
        let vk_bytes = STANDARD
            .decode(&self.perito.clave_publica)
            .map_err(|_| ErrorActa::ClaveMalFormada)?;
        let vk = TripleVerifyingKey::from_bytes(&vk_bytes).ok_or(ErrorActa::ClaveMalFormada)?;

        if vk.verify(&self.bytes_canonicos(), &sig) {
            Ok(())
        } else {
            Err(ErrorActa::FirmaInvalida)
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    pub fn acta_de_prueba() -> Acta {
        Acta {
            formato: FORMATO.to_string(),
            caso: Caso { referencia: "R-1".into(), descripcion: "prueba".into() },
            perito: Perito {
                nombre: "Perito".into(),
                identificacion: "CC 1".into(),
                clave_publica: String::new(),
            },
            adquisicion: Adquisicion {
                origen: "/tmp/x".into(),
                metodo: "copia lógica en solo lectura".into(),
                reloj: Reloj {
                    inicio_utc: "2026-07-26T10:00:00Z".into(),
                    fin_utc: "2026-07-26T10:00:01Z".into(),
                    desfase_local_utc: "-05:00".into(),
                    verificacion: "NO VERIFICADO".into(),
                },
                herramienta: "tunjo 0.1.0".into(),
                algoritmos: ALGORITMOS.into(),
            },
            elementos: vec![Elemento {
                ruta: "a.txt".into(),
                tipo: "archivo".into(),
                bytes: 3,
                sha256: "aa".into(),
                modificado_utc: "2026-07-26T09:00:00Z".into(),
                estado: "leido".into(),
                metodo_huella: String::new(),
            }],
            raiz_merkle: String::new(),
            firma: None,
            sello_tiempo: None,
        }
    }

    #[test]
    fn los_bytes_canonicos_no_dependen_de_la_firma() {
        let mut a = acta_de_prueba();
        let antes = a.bytes_canonicos();
        a.firma = Some(Firma { algoritmo: "x".into(), valor: "y".into() });
        assert_eq!(antes, a.bytes_canonicos(), "firmar no puede cambiar lo firmado");
    }

    #[test]
    fn los_bytes_canonicos_son_estables() {
        let a = acta_de_prueba();
        for _ in 0..50 {
            assert_eq!(a.bytes_canonicos(), acta_de_prueba().bytes_canonicos());
        }
    }

    #[test]
    fn cambiar_cualquier_campo_cambia_lo_firmado() {
        let base = acta_de_prueba().bytes_canonicos();
        let mut a = acta_de_prueba();
        a.elementos[0].sha256 = "bb".into();
        assert_ne!(base, a.bytes_canonicos());

        let mut b = acta_de_prueba();
        b.adquisicion.reloj.inicio_utc = "2026-07-26T10:00:02Z".into();
        assert_ne!(base, b.bytes_canonicos());

        let mut c = acta_de_prueba();
        c.caso.referencia = "R-2".into();
        assert_ne!(base, c.bytes_canonicos());
    }

    #[test]
    fn acta_sin_elementos_no_tiene_raiz() {
        let mut a = acta_de_prueba();
        a.elementos.clear();
        assert_eq!(a.fijar_raiz(), Err(ErrorActa::SinElementos));
    }

    #[test]
    fn una_raiz_mentirosa_se_detecta_aunque_la_firma_sea_valida() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let (vk, sk) = quipu::pqsign::generate_triple_keypair();
        let mut a = acta_de_prueba();
        a.perito.clave_publica = STANDARD.encode(vk.to_bytes());
        // Raíz que NO corresponde a los elementos, y firma auténtica encima.
        a.raiz_merkle = "00".repeat(32);
        let sig = sk.sign(&a.bytes_canonicos());
        a.firma = Some(Firma { algoritmo: ALGORITMOS.into(), valor: STANDARD.encode(&sig) });

        match a.verificar_sello() {
            Err(ErrorActa::RaizNoCoincide { .. }) => {}
            otro => panic!("la firma válida tapó una raíz falsa: {otro:?}"),
        }
    }
}

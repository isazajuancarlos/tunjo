// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Recorrido y hash del origen. **Solo lectura**: esta herramienta nunca
//! escribe dentro de lo que sella. Lo que no puede leer, lo dice.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::acta::{Elemento, hex};

/// Trozo de lectura. Los archivos se hashean por partes para que una imagen de
/// disco de 500 GB no exija 500 GB de RAM.
const TROZO: usize = 1 << 20;

fn ruta_relativa(base: &Path, ruta: &Path) -> String {
    let rel = ruta.strip_prefix(base).unwrap_or(ruta);
    // Separador `/` siempre: el acta se firma en una máquina y se verifica en
    // otra, y en Windows el separador nativo cambiaría los bytes firmados.
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn modificado(meta: &std::fs::Metadata) -> String {
    // Si el sistema de archivos no expone la fecha, queda VACÍA. No se
    // sustituye por la hora actual: un dato inventado en un acta es peor que
    // un dato ausente, porque nadie lo distingue del real.
    match meta.modified() {
        Ok(t) => DateTime::<Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        Err(_) => String::new(),
    }
}

fn hash_archivo(ruta: &Path) -> Result<(u64, String)> {
    let mut f = File::open(ruta)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; TROZO];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, hex(&h.finalize())))
}

/// Resultado del recorrido: los elementos y cuántos fallaron.
pub struct Recoleccion {
    pub elementos: Vec<Elemento>,
    pub ilegibles: Vec<String>,
}

/// Recorre `origen` —un archivo o un directorio— y devuelve sus elementos
/// ordenados por ruta.
///
/// El orden es alfabético y no el que devuelva el sistema de archivos: dos
/// adquisiciones del mismo material tienen que producir la misma raíz, y el
/// orden de `readdir` no está garantizado entre máquinas ni entre corridas.
pub fn recolectar(origen: &Path) -> Result<Recoleccion> {
    let origen = origen
        .canonicalize()
        .with_context(|| format!("no se puede acceder al origen {}", origen.display()))?;

    let mut elementos = Vec::new();
    let mut ilegibles = Vec::new();

    if origen.is_file() {
        let nombre = origen
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| origen.display().to_string());
        elementos.push(elemento_de_archivo(&origen, nombre, &mut ilegibles));
        return Ok(Recoleccion { elementos, ilegibles });
    }

    let mut entradas: Vec<PathBuf> = Vec::new();
    for e in WalkDir::new(&origen).follow_links(false).min_depth(1) {
        match e {
            Ok(e) => entradas.push(e.into_path()),
            Err(err) => ilegibles.push(format!(
                "{}: {err}",
                err.path().map(|p| p.display().to_string()).unwrap_or_else(|| "?".into())
            )),
        }
    }
    entradas.sort();

    for ruta in entradas {
        let rel = ruta_relativa(&origen, &ruta);
        let meta = match std::fs::symlink_metadata(&ruta) {
            Ok(m) => m,
            Err(err) => {
                ilegibles.push(format!("{rel}: {err}"));
                elementos.push(Elemento {
                    ruta: rel,
                    tipo: "desconocido".into(),
                    bytes: 0,
                    sha256: String::new(),
                    modificado_utc: String::new(),
                    estado: format!("ERROR: {err}"),
                    metodo_huella: String::new(),
                });
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            // No se sigue el enlace: se registra a dónde apunta. Seguirlo
            // sacaría al perito del material que le entregaron.
            let destino = std::fs::read_link(&ruta)
                .map(|d| d.display().to_string())
                .unwrap_or_else(|_| "?".into());
            elementos.push(Elemento {
                ruta: rel,
                tipo: "enlace".into(),
                bytes: 0,
                sha256: String::new(),
                modificado_utc: modificado(&meta),
                estado: format!("enlace -> {destino}"),
                metodo_huella: String::new(),
            });
        } else if meta.is_dir() {
            elementos.push(Elemento {
                ruta: rel,
                tipo: "directorio".into(),
                bytes: 0,
                sha256: String::new(),
                modificado_utc: modificado(&meta),
                estado: "directorio".into(),
                metodo_huella: String::new(),
            });
        } else {
            elementos.push(elemento_de_archivo(&ruta, rel, &mut ilegibles));
        }
    }

    Ok(Recoleccion { elementos, ilegibles })
}

fn elemento_de_archivo(ruta: &Path, rel: String, ilegibles: &mut Vec<String>) -> Elemento {
    let meta = std::fs::symlink_metadata(ruta).ok();
    let modificado_utc = meta.as_ref().map(modificado).unwrap_or_default();
    match hash_archivo(ruta) {
        Ok((bytes, sha)) => Elemento {
            ruta: rel,
            tipo: "archivo".into(),
            bytes,
            sha256: sha,
            modificado_utc,
            estado: "leido".into(),
            metodo_huella: String::new(),
        },
        Err(err) => {
            ilegibles.push(format!("{rel}: {err}"));
            Elemento {
                ruta: rel,
                tipo: "archivo".into(),
                bytes: meta.map(|m| m.len()).unwrap_or(0),
                sha256: String::new(),
                modificado_utc,
                estado: format!("ERROR: {err}"),
                metodo_huella: String::new(),
            }
        }
    }
}

/// Vuelve a leer el origen y compara con lo que dice el acta.
#[derive(Debug, PartialEq)]
pub enum Discrepancia {
    Alterado { ruta: String, esperado: String, encontrado: String },
    Ausente { ruta: String },
    NoEstabaEnElActa { ruta: String },
    NoVerificable { ruta: String, motivo: String },
}

/// Se sanea CADA CAMPO aquí dentro, no alrededor del `{d}` en quien imprime.
///
/// La sexta revisión encontró que el bloque de `--origen` imprimía esta lista en
/// crudo, y era la QUINTA aparición de la misma clase: el saneo se aplicaba rama
/// por rama en `main.rs` y siempre faltaba una. Un `ruta` con escapes de terminal
/// borraba las líneas de ALTERADO y pintaba encima «material íntegro» — en el
/// comando que el propio documento le dice al lector que ejecute.
///
/// Va por campo y no envolviendo el valor entero porque `Alterado` emite saltos de
/// línea a propósito: aplanar el conjunto rompería la disposición que hace legible
/// la comparación.
impl std::fmt::Display for Discrepancia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Local para no depender de otro módulo desde aquí: es la misma regla que
        // `informe::plano` —todo carácter de control pasa a espacio— y su sitio
        // natural es este, el punto donde el texto ajeno se convierte en salida.
        let p = |s: &str| -> String {
            s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
        };
        match self {
            Self::Alterado { ruta, esperado, encontrado } => write!(
                f,
                "ALTERADO   {}\n           acta: {}\n           disco: {}",
                p(ruta),
                p(esperado),
                p(encontrado)
            ),
            Self::Ausente { ruta } => {
                write!(f, "AUSENTE    {} (está en el acta, no en el disco)", p(ruta))
            }
            Self::NoEstabaEnElActa { ruta } => {
                write!(f, "AÑADIDO    {} (está en el disco, no en el acta)", p(ruta))
            }
            Self::NoVerificable { ruta, motivo } => {
                write!(f, "SIN LEER   {}: {}", p(ruta), p(motivo))
            }
        }
    }
}

/// Contrasta el acta contra el contenido actual de `origen`.
pub fn contrastar(elementos: &[Elemento], origen: &Path) -> Result<Vec<Discrepancia>> {
    let actual = recolectar(origen)?;
    let mut discrepancias = Vec::new();

    for esperado in elementos {
        // Un elemento sellado con OTRO método no se verifica leyendo bytes, y
        // recomputar el SHA-256 del archivo daría ALTERADO en cada verificación
        // aunque todo esté bien. Se dice que hace falta otra herramienta; no se
        // da por bueno ni por alterado.
        if !esperado.metodo_huella.is_empty() {
            match actual.elementos.iter().find(|e| e.ruta == esperado.ruta) {
                None => discrepancias.push(Discrepancia::Ausente {
                    ruta: esperado.ruta.clone(),
                }),
                Some(_) => discrepancias.push(Discrepancia::NoVerificable {
                    ruta: esperado.ruta.clone(),
                    motivo: format!(
                        "sellado con «{}»: el archivo está, pero su huella no se \
                         comprueba leyendo bytes. Verifíquelo con la herramienta \
                         de ese método y compare contra el acta.",
                        esperado.metodo_huella
                    ),
                }),
            }
            continue;
        }

        match actual.elementos.iter().find(|e| e.ruta == esperado.ruta) {
            None => discrepancias.push(Discrepancia::Ausente { ruta: esperado.ruta.clone() }),
            Some(hallado) => {
                if hallado.tipo != esperado.tipo {
                    // Un archivo donde había un enlace —o al revés— es un
                    // cambio de estado aunque el contenido cuadre.
                    discrepancias.push(Discrepancia::Alterado {
                        ruta: esperado.ruta.clone(),
                        esperado: format!("{} ({})", esperado.tipo, esperado.estado),
                        encontrado: format!("{} ({})", hallado.tipo, hallado.estado),
                    });
                } else if esperado.tipo == "enlace" {
                    // Un enlace no tiene contenido que hashear: lo que hay que
                    // vigilar es a dónde apunta. Sin esto, reapuntarlo a otro
                    // archivo pasaba inadvertido.
                    if hallado.estado != esperado.estado {
                        discrepancias.push(Discrepancia::Alterado {
                            ruta: esperado.ruta.clone(),
                            esperado: esperado.estado.clone(),
                            encontrado: hallado.estado.clone(),
                        });
                    }
                } else if esperado.estado.starts_with("ERROR") || esperado.sha256.is_empty() {
                    // No se puede afirmar que coincide algo que nunca se leyó.
                    // Se dice, no se da por bueno.
                    if esperado.tipo == "archivo" {
                        discrepancias.push(Discrepancia::NoVerificable {
                            ruta: esperado.ruta.clone(),
                            motivo: format!("en el acta consta «{}»", esperado.estado),
                        });
                    }
                } else if hallado.sha256 != esperado.sha256 {
                    discrepancias.push(Discrepancia::Alterado {
                        ruta: esperado.ruta.clone(),
                        esperado: esperado.sha256.clone(),
                        encontrado: if hallado.sha256.is_empty() {
                            hallado.estado.clone()
                        } else {
                            hallado.sha256.clone()
                        },
                    });
                }
            }
        }
    }

    for hallado in &actual.elementos {
        if !elementos.iter().any(|e| e.ruta == hallado.ruta) {
            discrepancias.push(Discrepancia::NoEstabaEnElActa { ruta: hallado.ruta.clone() });
        }
    }

    Ok(discrepancias)
}

// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
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

/// Formatea un instante del sistema de archivos a UTC, o VACÍO si el FS no lo
/// expone. No se sustituye por la hora actual: un dato inventado en un acta es
/// peor que un dato ausente, porque nadie lo distingue del real (D20). Es el
/// único sitio que decide esto, para que las tres marcas (M/A/C) lo hagan igual.
fn instante(t: std::io::Result<std::time::SystemTime>) -> String {
    match t {
        Ok(t) => DateTime::<Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        Err(_) => String::new(),
    }
}

fn modificado(meta: &std::fs::Metadata) -> String {
    instante(meta.modified())
}

/// Último acceso (atime). Vacío si el FS no lo expone o el montaje usa `noatime`.
fn accedido(meta: &std::fs::Metadata) -> String {
    instante(meta.accessed())
}

/// Creación (btime). Vacío si el FS o el kernel no la exponen — muchos no la dan.
fn creado(meta: &std::fs::Metadata) -> String {
    instante(meta.created())
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
                    accedido_utc: String::new(),
                    creado_utc: String::new(),
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
                accedido_utc: accedido(&meta),
                creado_utc: creado(&meta),
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
                // VACÍO a propósito, NO `accedido(&meta)`: `WalkDir` recorre el
                // árbol ENTERO antes de este bucle, y leer un directorio (readdir)
                // actualiza SU atime. Para un directorio, el atime que leeríamos
                // aquí sería el del propio recorrido de tunjo —el instante del
                // sellado—, no un acceso anterior: un dato que la herramienta
                // causó y parece evidencia (D20, peor que ausente). Para archivos
                // no pasa (su contenido se lee en `hash_archivo`, DESPUÉS de tomar
                // `meta`). Lo cazó el concilio del 2026-10-12 (haiku+fable, 8).
                accedido_utc: String::new(),
                creado_utc: creado(&meta),
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
    let accedido_utc = meta.as_ref().map(accedido).unwrap_or_default();
    let creado_utc = meta.as_ref().map(creado).unwrap_or_default();
    match hash_archivo(ruta) {
        Ok((bytes, sha)) => Elemento {
            ruta: rel,
            tipo: "archivo".into(),
            bytes,
            sha256: sha,
            modificado_utc,
            accedido_utc,
            creado_utc,
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
                accedido_utc,
                creado_utc,
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
        // El ÚNICO sitio de neutralización es `texto::plano`, y esta salida de
        // pantalla (verificar --origen) DEBE pasar por él: el nombre de un archivo
        // incautado —`esperado.ruta`, `encontrado`— es texto ajeno, y un RLO o un
        // ancho cero en él llegaría al terminal del perito reordenado u oculto.
        // Aquí había una copia local que solo veía is_control —la duplicación que
        // `texto` existe para eliminar—; lo cazó el concilio del 2026-10-12.
        let p = |s: &str| crate::texto::plano(s);
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

#[cfg(test)]
mod pruebas {
    use super::*;

    /// La salida de pantalla de `verificar --origen` DEBE pasar por `texto::plano`:
    /// el nombre de un archivo incautado con RLO o ancho cero no puede llegar al
    /// terminal del perito sin neutralizar. Caso rojo por la vía real —el `Display`
    /// de `Discrepancia`—, que la copia local anterior (solo is_control) no cubría.
    #[test]
    fn el_display_de_discrepancia_neutraliza_invisibles_y_bidi() {
        // Un RLO en el nombre + anchos cero/BOM/tag en los demás campos. (El `\n` de
        // la disposición de `Alterado` es estructura legítima, no se mide aquí.)
        let dañino = "factura\u{202E}gpj.exe\u{E0041}";
        for d in [
            Discrepancia::NoEstabaEnElActa { ruta: dañino.into() },
            Discrepancia::Ausente { ruta: dañino.into() },
            Discrepancia::Alterado {
                ruta: dañino.into(),
                esperado: "a".into(),
                encontrado: "fac\u{200B}tura".into(),
            },
            Discrepancia::NoVerificable { ruta: dañino.into(), motivo: "x\u{FEFF}y".into() },
        ] {
            let s = d.to_string();
            for peligroso in ['\u{202E}', '\u{200B}', '\u{FEFF}', '\u{E0041}'] {
                assert!(
                    !s.contains(peligroso),
                    "U+{:04X} llegó a la salida de pantalla: {s:?}",
                    peligroso as u32
                );
            }
        }
    }

    /// El atime de un DIRECTORIO queda VACÍO: `WalkDir` ya recorrió el árbol antes
    /// de que midamos la metadata, y leer un directorio actualiza su atime, así que
    /// `accedido(&meta)` daría el instante del propio sellado —un dato que la
    /// herramienta causó (D20), no un acceso real—. Lo cazó el concilio del
    /// 2026-10-12 (haiku+fable, confianza 8). El MUTANTE es el código anterior
    /// (`accedido_utc: accedido(&meta)` en la rama de directorio): sobre un
    /// directorio recién creado habría puesto su atime, y este assert se pone rojo.
    /// Pareja D33: el ARCHIVO del mismo recorrido NO se vacía (trae su mtime), así
    /// que la recolección no está cegando todas las marcas, solo la contaminada.
    #[test]
    fn el_atime_de_un_directorio_queda_vacio() {
        let raiz = tempfile::tempdir().unwrap();
        std::fs::create_dir(raiz.path().join("sub")).unwrap();
        std::fs::write(raiz.path().join("sub/a.txt"), b"hola").unwrap();

        let rec = recolectar(raiz.path()).unwrap();

        let subdir = rec
            .elementos
            .iter()
            .find(|e| e.tipo == "directorio")
            .expect("el recorrido incluye el subdirectorio");
        assert!(
            subdir.accedido_utc.is_empty(),
            "el atime del directorio «{}» no quedó vacío ({:?}): sería el del propio \
             sellado, no un acceso real (D20)",
            subdir.ruta,
            subdir.accedido_utc,
        );

        // Control: un archivo del mismo recorrido SÍ trae su mtime — la recolección
        // puebla las marcas honestas, no las vacía todas.
        let archivo = rec
            .elementos
            .iter()
            .find(|e| e.tipo == "archivo")
            .expect("el recorrido incluye el archivo");
        assert!(
            !archivo.modificado_utc.is_empty(),
            "el archivo debería traer su mtime: la recolección no lee marcas",
        );
    }
}

// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Interfaz de línea de órdenes de Tunjo.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};

use tunjo::acta::{Acta, Elemento};
use tunjo::{clave, informe, recoleccion, sellado};

#[derive(Parser)]
#[command(
    name = "tunjo",
    version,
    about = "Sella evidencia digital y levanta el acta de cadena de custodia",
    long_about = "Sella evidencia digital con firma post-cuántica y levanta el acta de \
                  cadena de custodia.\n\nNo interpreta ni concluye: acredita qué se recogió, \
                  cuándo y quién responde. La lectura de esos hechos es del dictamen."
)]
struct Cli {
    #[command(subcommand)]
    orden: Orden,
}

#[derive(Subcommand)]
enum Orden {
    /// Crea la clave de firma del perito (cifrada con contraseña).
    Clave {
        /// Dónde se guarda.
        #[arg(long, default_value = "perito.clave")]
        ruta: PathBuf,
        /// Muestra la clave pública de una clave ya existente.
        #[arg(long)]
        publica: bool,
    },
    /// Recorre el origen, calcula la raíz de integridad y firma el acta.
    Sellar {
        /// Archivo o directorio a sellar. Se lee, nunca se escribe.
        origen: PathBuf,
        #[arg(long, default_value = "perito.clave")]
        clave: PathBuf,
        /// Radicado o referencia con la que se citará el acta.
        #[arg(long)]
        referencia: String,
        /// Qué se está sellando y en el marco de qué actuación.
        #[arg(long)]
        descripcion: String,
        #[arg(long)]
        perito: String,
        /// Cédula o tarjeta profesional del perito.
        #[arg(long)]
        identificacion: String,
        /// Cómo se obtuvo el material (bloqueador de escritura, copia lógica…).
        #[arg(long, default_value = "copia lógica en solo lectura")]
        metodo: String,
        /// Cómo se contrastó el reloj con una fuente externa. Si se omite, el
        /// acta dirá que NO se verificó — no se supone que estaba bien.
        #[arg(long)]
        reloj: Option<String>,
        /// Registrar y firmar aunque haya elementos ilegibles. Sin esto, un
        /// archivo que no se pudo leer detiene el sellado.
        #[arg(long)]
        admitir_ilegibles: bool,
        /// URL de una autoridad de sellado de tiempo RFC 3161. Sin esto el acta
        /// prueba orden relativo, no fecha cierta oponible a terceros.
        #[arg(long, value_name = "URL")]
        sello: Option<String>,
        #[arg(long, default_value = "acta.json")]
        salida: PathBuf,
    },
    /// Verifica la firma del acta y, si se indica el origen, el material.
    Verificar {
        acta: PathBuf,
        /// Contrasta además contra el contenido actual de esta ruta.
        #[arg(long)]
        origen: Option<PathBuf>,
    },
    /// Genera el acta legible (Markdown) a partir del JSON firmado.
    Acta {
        acta: PathBuf,
        /// Dónde escribirla. Si se omite, sale por pantalla.
        #[arg(long)]
        salida: Option<PathBuf>,
    },
}

fn leer_acta(ruta: &Path) -> Result<Acta> {
    let texto = std::fs::read_to_string(ruta)
        .with_context(|| format!("leyendo el acta {}", ruta.display()))?;
    serde_json::from_str(&texto).with_context(|| format!("el acta {} no es válida", ruta.display()))
}

/// Variable con la que se automatiza el sellado por lotes.
///
/// Existe porque sellar cincuenta elementos de un caso a mano no es una
/// operación rara: es la normal. Sin esto el CLI exige un terminal y no se
/// puede guionizar. Es opt-in explícito y tiene su coste —la contraseña queda
/// en el entorno del proceso—, así que se dice aquí y en el README.
const VAR_CONTRASENA: &str = "TUNJO_CONTRASENA";

fn pedir_contrasena(confirmar: bool) -> Result<String> {
    if let Ok(p) = std::env::var(VAR_CONTRASENA) {
        if p.trim().is_empty() {
            bail!("{VAR_CONTRASENA} está definida pero vacía");
        }
        return Ok(p);
    }
    let p = rpassword::prompt_password("Contraseña de la clave del perito: ")?;
    if p.trim().is_empty() {
        bail!("una clave de firma sin contraseña no protege nada");
    }
    if confirmar {
        let otra = rpassword::prompt_password("Repítela: ")?;
        if p != otra {
            bail!("las contraseñas no coinciden");
        }
    }
    Ok(p)
}

fn orden_clave(ruta: PathBuf, publica: bool) -> Result<()> {
    if publica {
        let sk = clave::cargar(&ruta, &pedir_contrasena(false)?)?;
        println!("{}", STANDARD.encode(sk.verifying_key().to_bytes()));
        return Ok(());
    }
    let vk = clave::generar(&ruta, &pedir_contrasena(true)?)?;
    println!("Clave creada en {}", ruta.display());
    println!("Clave pública (publicable, es la que verifica tus actas):");
    println!("{}", STANDARD.encode(vk.to_bytes()));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn orden_sellar(
    origen: PathBuf,
    ruta_clave: PathBuf,
    referencia: String,
    descripcion: String,
    perito: String,
    identificacion: String,
    metodo: String,
    reloj: Option<String>,
    admitir_ilegibles: bool,
    autoridad_sello: Option<String>,
    salida: PathBuf,
) -> Result<()> {
    if salida.exists() {
        bail!(
            "ya existe {} — un acta no se sobrescribe; elige otra salida",
            salida.display()
        );
    }
    let sk = clave::cargar(&ruta_clave, &pedir_contrasena(false)?)?;

    let acta = sellado::sellar(
        &origen,
        &sk,
        &sellado::Datos {
            referencia,
            descripcion,
            perito,
            identificacion,
            metodo,
            reloj,
            admitir_ilegibles,
            autoridad_sello,
        },
    )?;

    std::fs::write(&salida, serde_json::to_vec_pretty(&acta)?)?;

    let leidos = acta.elementos.iter().filter(|e| e.estado == "leido").count();
    let ilegibles = acta.elementos.iter().filter(|e| e.estado.starts_with("ERROR")).count();
    println!("Acta sellada en {}", salida.display());
    println!("  elementos:  {} ({leidos} leídos)", acta.elementos.len());
    if ilegibles > 0 {
        println!("  ILEGIBLES:  {ilegibles} (constan en el acta)");
    }
    println!("  raíz:       {}", acta.raiz_merkle);
    match &acta.sello_tiempo {
        Some(s) => println!("  sello:      {} — {}", s.fecha_utc, s.autoridad),
        None => println!("  sello:      SIN SELLO DE TIEMPO (prueba orden relativo, no fecha cierta)"),
    }
    Ok(())
}

fn resumen_elementos(elementos: &[Elemento]) -> String {
    let leidos = elementos.iter().filter(|e| e.estado == "leido").count();
    format!("{} elementos, {leidos} con contenido verificable", elementos.len())
}

fn orden_verificar(ruta: PathBuf, origen: Option<PathBuf>) -> Result<bool> {
    let acta = leer_acta(&ruta)?;

    match acta.verificar_sello() {
        Ok(()) => {
            println!("SELLO VÁLIDO");
            println!("  referencia: {}", acta.caso.referencia);
            println!("  perito:     {} ({})", acta.perito.nombre, acta.perito.identificacion);
            println!("  adquirido:  {}", acta.adquisicion.reloj.inicio_utc);
            println!("  contenido:  {}", resumen_elementos(&acta.elementos));
            println!("  raíz:       {}", acta.raiz_merkle);
        }
        Err(e) => {
            println!("SELLO INVÁLIDO: {e}");
            return Ok(false);
        }
    }

    // El sello de tiempo se verifica aparte y su ausencia NO invalida el acta:
    // es un límite declarado, no un defecto. Lo que sí invalida es llevar uno
    // que sella otra cosa.
    match acta.verificar_sello_tiempo() {
        Ok(Some(t)) => {
            println!("  fecha cierta: {} (autoridad RFC 3161)", t.fecha_utc);
            println!("  política:     {}", t.politica);
        }
        Ok(None) => println!(
            "  fecha cierta: NO — el acta no lleva sello de tiempo de un tercero,\n\
             \x20               así que prueba orden relativo, no fecha oponible"
        ),
        Err(e) => {
            println!("SELLO DE TIEMPO INVÁLIDO: {e}");
            return Ok(false);
        }
    }

    let Some(origen) = origen else {
        println!("\n(no se contrastó contra el disco: usa --origen RUTA para hacerlo)");
        return Ok(true);
    };

    let discrepancias = recoleccion::contrastar(&acta.elementos, &origen)?;
    if discrepancias.is_empty() {
        println!("\nMATERIAL ÍNTEGRO: {} coincide byte a byte con el acta.", origen.display());
        return Ok(true);
    }
    println!("\n{} DISCREPANCIA(S) contra {}:\n", discrepancias.len(), origen.display());
    for d in &discrepancias {
        println!("{d}");
    }
    Ok(false)
}

fn orden_acta(ruta: PathBuf, salida: Option<PathBuf>) -> Result<()> {
    let acta = leer_acta(&ruta)?;
    // Se avisa, pero se genera igual: un acta sin firmar también hay que poder
    // leerla para revisarla antes de sellar.
    if let Err(e) = acta.verificar_sello() {
        eprintln!("AVISO: el sello de esta acta no es válido ({e}).");
        eprintln!("El documento se genera igualmente, pero NO acredita integridad.");
    }
    let md = informe::markdown(&acta);
    match salida {
        Some(s) => {
            std::fs::write(&s, md)?;
            println!("Acta escrita en {}", s.display());
        }
        None => print!("{md}"),
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let resultado = match cli.orden {
        Orden::Clave { ruta, publica } => orden_clave(ruta, publica).map(|_| true),
        Orden::Sellar {
            origen,
            clave,
            referencia,
            descripcion,
            perito,
            identificacion,
            metodo,
            reloj,
            admitir_ilegibles,
            sello,
            salida,
        } => orden_sellar(
            origen,
            clave,
            referencia,
            descripcion,
            perito,
            identificacion,
            metodo,
            reloj,
            admitir_ilegibles,
            sello,
            salida,
        )
        .map(|_| true),
        Orden::Verificar { acta, origen } => orden_verificar(acta, origen),
        Orden::Acta { acta, salida } => orden_acta(acta, salida).map(|_| true),
    };

    match resultado {
        // Código 1 reservado a «la verificación falló», distinto del 2 de un
        // error de operación: un guion que verifique actas necesita
        // distinguirlos.
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

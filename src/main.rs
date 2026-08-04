// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Interfaz de línea de órdenes de Tunjo.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand};

use tunjo::acta::{Acta, Elemento};
use tunjo::custodia::{self, Evento};
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
        /// PEM con el certificado de la autoridad de sellado en el que decides
        /// confiar. Sin esto la firma del sello se comprueba igual, pero la
        /// IDENTIDAD de la autoridad no queda acreditada y no se llama «fecha
        /// cierta» a la fecha. No hay lista por defecto a propósito.
        #[arg(long = "tsa-ca")]
        tsa_ca: Option<PathBuf>,
    },
    /// Genera el acta legible (Markdown) a partir del JSON firmado.
    Acta {
        acta: PathBuf,
        /// Dónde escribirla. Si se omite, sale por pantalla.
        #[arg(long)]
        salida: Option<PathBuf>,
        /// PEM de la autoridad de sellado en la que confías. Sin esto el documento
        /// NO afirmará fecha cierta, aunque el sello lleve firma válida.
        #[arg(long = "tsa-ca")]
        tsa_ca: Option<PathBuf>,
    },
    /// Cadena de custodia: la secuencia de eventos sobre una evidencia sellada.
    Custodia {
        #[command(subcommand)]
        accion: Custodia,
    },
}

#[derive(Subcommand)]
enum Custodia {
    /// Inicia la cadena sobre un acta ya sellada (evento de adquisición).
    Iniciar {
        #[arg(long, default_value = "acta.json")]
        acta: PathBuf,
        #[arg(long, default_value = "perito.clave")]
        clave: PathBuf,
        #[arg(long, default_value = "cadena.json")]
        salida: PathBuf,
        /// Quién recogió la evidencia.
        #[arg(long)]
        actor: String,
        /// Cédula o tarjeta profesional del actor.
        #[arg(long)]
        identificacion: String,
        #[arg(long, default_value = "perito")]
        rol: String,
        /// Cómo se contrastó el reloj. Si se omite, queda NO VERIFICADO.
        #[arg(long)]
        reloj: Option<String>,
        /// Qué se recogió y cómo.
        #[arg(long)]
        descripcion: String,
    },
    /// Añade un evento (transferencia, análisis, almacenamiento…) a la cadena.
    Evento {
        #[arg(long, default_value = "cadena.json")]
        cadena: PathBuf,
        #[arg(long, default_value = "perito.clave")]
        clave: PathBuf,
        /// `transferencia`, `analisis`, `almacenamiento`, `presentacion`…
        #[arg(long)]
        tipo: String,
        /// Quién ejecuta el evento.
        #[arg(long)]
        actor: String,
        #[arg(long)]
        identificacion: String,
        #[arg(long)]
        rol: String,
        #[arg(long)]
        reloj: Option<String>,
        #[arg(long)]
        descripcion: String,
    },
    /// Sella el último eslabón contra una autoridad de tiempo RFC 3161, para que
    /// truncar la cadena por el final sea detectable y toda ella tenga fecha cierta.
    Sello {
        #[arg(long, default_value = "cadena.json")]
        cadena: PathBuf,
        /// URL de la autoridad de sellado (RFC 3161), p. ej. http://timestamp.digicert.com
        #[arg(long)]
        sello: String,
    },
    /// Verifica la cadena (eslabones, firmas triple, secuencia) y, con --acta, el ancla.
    Verificar {
        #[arg(long, default_value = "cadena.json")]
        cadena: PathBuf,
        /// Comprueba además que la cadena corresponde a esta acta.
        #[arg(long)]
        acta: Option<PathBuf>,
        /// PEM con el certificado —o los certificados— de la autoridad de sellado
        /// en los que decides confiar, normalmente su raíz. Sin esto la firma del
        /// sello se comprueba igual, pero su IDENTIDAD no queda acreditada: un
        /// autofirmado con el uso de sellado pasa la comprobación criptográfica.
        /// No hay lista por defecto a propósito: en quién confías no lo decide
        /// esta herramienta.
        #[arg(long = "tsa-ca")]
        tsa_ca: Option<PathBuf>,
    },
}

fn leer_acta(ruta: &Path) -> Result<Acta> {
    let texto = std::fs::read_to_string(ruta)
        .with_context(|| format!("leyendo el acta {}", ruta.display()))?;
    serde_json::from_str(&texto).with_context(|| format!("el acta {} no es válida", ruta.display()))
}

/// Lee las anclas de confianza de `--tsa-ca`, o ninguna si no se pidieron.
///
/// Si se pidió y el archivo no sirve, se FALLA: quien pasa `--tsa-ca` está
/// exigiendo ese control, y seguir sin él en silencio daría por acreditado lo que
/// no lo está (directiva de fallar en vez de suponer).
fn leer_anclas(ruta: Option<&Path>) -> Result<Vec<x509_cert::Certificate>> {
    let Some(p) = ruta else {
        return Ok(Vec::new());
    };
    let pem = std::fs::read_to_string(p)
        .with_context(|| format!("leyendo las anclas {}", p.display()))?;
    tunjo::firma_cms::anclas_desde_pem(&pem)
        .with_context(|| format!("las anclas de {}", p.display()))
}

/// Variable con la que se automatiza el sellado por lotes.
///
/// Existe porque sellar cincuenta elementos de un caso a mano no es una
/// operación rara: es la normal. Sin esto el CLI exige un terminal y no se
/// puede guionizar. Es opt-in explícito y tiene su coste —la contraseña queda
/// en el entorno del proceso—, así que se dice aquí y en el README.
const VAR_CONTRASENA: &str = "TUNJO_CONTRASENA";

/// Lo que hay que decir cuando no hay terminal donde preguntar.
///
/// Sin esto, `rpassword` propaga el error del sistema en crudo y un guion sin
/// tty muere con «No such device or address (os error 6)», que no nombra ni la
/// contraseña ni la variable que lo resuelve. Es el caso normal de un sellado
/// por lotes, no un caso raro (2026-08-04).
const SIN_TERMINAL: &str = "no hay terminal donde pedir la contraseña; \
     para uso no interactivo (lotes, guiones, CI) pásala en TUNJO_CONTRASENA";

fn pedir_contrasena(confirmar: bool) -> Result<String> {
    if let Ok(p) = std::env::var(VAR_CONTRASENA) {
        if p.trim().is_empty() {
            bail!("{VAR_CONTRASENA} está definida pero vacía");
        }
        return Ok(p);
    }
    let p = rpassword::prompt_password("Contraseña de la clave del perito: ")
        .context(SIN_TERMINAL)?;
    if p.trim().is_empty() {
        bail!("una clave de firma sin contraseña no protege nada");
    }
    if confirmar {
        let otra = rpassword::prompt_password("Repítela: ").context(SIN_TERMINAL)?;
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
    // La regla de qué es «verificable» —por la EVIDENCIA y no por el estado
    // declarado— vive en UN sitio, `informe::verificables`. Estuvo copiada aquí y
    // en el generador del documento, y esa es la forma en que dos conteos que
    // deberían decir lo mismo se separan sin que nadie lo note.
    format!(
        "{} elementos, {} con contenido verificable",
        elementos.len(),
        informe::verificables(elementos)
    )
}

fn orden_verificar(
    ruta: PathBuf,
    origen: Option<PathBuf>,
    tsa_ca: Option<PathBuf>,
) -> Result<bool> {
    let anclas = leer_anclas(tsa_ca.as_deref())?;
    let acta = leer_acta(&ruta)?;

    match acta.verificar_sello() {
        Ok(()) => {
            println!("SELLO VÁLIDO");
            // Todo campo del JSON pasa por `plano`. La firma que acaba de verificar
            // es la del PROPIO autor del acta, no la de nadie de confianza: estos
            // cuatro textos los elige quien la entrega, y un salto de línea con un
            // «oculta lo siguiente» replicaba un veredicto anclado completo y
            // escondía las líneas reales. Quinta revisión — el mismo hallazgo de la
            // cuarta, una rama más allá.
            println!("  referencia: {}", informe::plano(&acta.caso.referencia));
            println!(
                "  perito:     {} ({})",
                informe::plano(&acta.perito.nombre),
                informe::plano(&acta.perito.identificacion)
            );
            println!("  adquirido:  {}", informe::plano(&acta.adquisicion.reloj.inicio_utc));
            println!("  contenido:  {}", resumen_elementos(&acta.elementos));
            println!("  raíz:       {}", acta.raiz_merkle);
        }
        Err(e) => {
            println!("SELLO INVÁLIDO: {}", informe::plano(&e.to_string()));
            return Ok(false);
        }
    }

    // El sello de tiempo se verifica aparte y su ausencia NO invalida el acta:
    // es un límite declarado, no un defecto. Lo que sí invalida es llevar uno
    // que sella otra cosa.
    match acta.verificar_sello_tiempo(&anclas) {
        Ok(Some((t, confianza))) => {
            if confianza.acredita_autoridad() {
                println!("  fecha cierta: {} (RFC 3161)", t.fecha_utc);
                println!("  autoridad:    {} — anclada", confianza.autoridad());
            } else {
                // Firma válida pero anónima: no se llama «fecha cierta» a algo que
                // un autofirmado produce igual.
                println!(
                    "  fecha:        {} — firma válida, pero SIN ANCLAR",
                    t.fecha_utc
                );
                println!(
                    "  autoridad:    «{}», identidad NO acreditada.\n\
                     \x20               Exígela con `--tsa-ca <raíz.pem>`.",
                    confianza.autoridad()
                );
            }
            println!("  política:     {}", t.politica);
        }
        Ok(None) => println!(
            "  fecha cierta: NO — el acta no lleva sello de tiempo de un tercero,\n\
             \x20               así que prueba orden relativo, no fecha oponible"
        ),
        Err(e) => {
            println!("SELLO DE TIEMPO INVÁLIDO: {}", informe::plano(&e.to_string()));
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

fn orden_acta(ruta: PathBuf, salida: Option<PathBuf>, tsa_ca: Option<PathBuf>) -> Result<bool> {
    let acta = leer_acta(&ruta)?;
    // El documento se genera igual —hay que poder leer un acta para revisarla—,
    // pero el veredicto viaja DENTRO de él y además decide el código de salida.
    // Antes eran dos líneas en stderr: no llegan al juzgado, y cualquier
    // redirección o `--salida` las perdía mientras el documento seguía afirmando
    // integridad. Lo cazó la tercera revisión de seguridad.
    let verificada = match acta.verificar_sello() {
        Ok(()) => informe::ActaVerificada::Valida,
        Err(e) => {
            eprintln!("AVISO: la firma de esta acta NO verifica ({}).", informe::plano(&e.to_string()));
            informe::ActaVerificada::Invalida(e.to_string())
        }
    };
    // El documento legible NO puede afirmar la fecha leyéndola del JSON: eso es un
    // dato de quien entrega el acta. Se verifica aquí y se le pasa el VEREDICTO.
    let anclas = leer_anclas(tsa_ca.as_deref())?;
    let sello = match acta.verificar_sello_tiempo(&anclas) {
        Ok(Some((datos, confianza))) => informe::SelloVerificado::Valido(datos, confianza),
        Ok(None) => informe::SelloVerificado::Ausente,
        Err(e) => {
            eprintln!("AVISO: el sello de tiempo de esta acta NO es válido ({}).", informe::plano(&e.to_string()));
            informe::SelloVerificado::Invalido(e.to_string())
        }
    };
    let md = informe::markdown(&acta, &verificada, &sello);
    match salida {
        Some(s) => {
            std::fs::write(&s, md)?;
            println!("Acta escrita en {}", s.display());
        }
        None => print!("{md}"),
    }
    // `tunjo acta` no puede ser MÁS PERMISIVO que `tunjo verificar` sobre el mismo
    // archivo: quien entrega un acta forjada sugeriría el comando que sale con 0.
    let bien = matches!(verificada, informe::ActaVerificada::Valida)
        && !matches!(sello, informe::SelloVerificado::Invalido(_));
    Ok(bien)
}

fn ahora_utc() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Huella corta (SHA-256, 8 bytes en hex) de una clave pública. La clave triple
/// ocupa 46 KB en base64 y nadie coteja eso a ojo; la huella sí. Es el mismo
/// criterio que el acta legible.
fn huella_clave(clave_b64: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(clave_b64.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

const RELOJ_SIN_VERIFICAR: &str = "NO VERIFICADO contra fuente externa de tiempo";

fn orden_custodia(accion: Custodia) -> Result<bool> {
    match accion {
        Custodia::Iniciar {
            acta,
            clave,
            salida,
            actor,
            identificacion,
            rol,
            reloj,
            descripcion,
        } => {
            if salida.exists() {
                bail!(
                    "ya existe {} — una cadena de custodia no se sobrescribe; elige otra salida",
                    salida.display()
                );
            }
            let a = leer_acta(&acta)?;
            let sk = clave::cargar(&clave, &pedir_contrasena(false)?)?;
            let evento = Evento {
                tipo: "adquisicion".into(),
                actor,
                identificacion,
                rol,
                fecha_utc: ahora_utc(),
                reloj: reloj.unwrap_or_else(|| RELOJ_SIN_VERIFICAR.into()),
                descripcion,
            };
            let cadena = custodia::iniciar(&a.bytes_canonicos(), evento, &sk);
            std::fs::write(&salida, serde_json::to_vec_pretty(&cadena)?)?;
            println!(
                "Cadena de custodia iniciada en {} (anclada al acta {}).",
                salida.display(),
                acta.display()
            );
            Ok(true)
        }
        Custodia::Evento {
            cadena: ruta,
            clave,
            tipo,
            actor,
            identificacion,
            rol,
            reloj,
            descripcion,
        } => {
            let texto = std::fs::read_to_string(&ruta)
                .with_context(|| format!("leyendo la cadena {}", ruta.display()))?;
            let mut cadena = custodia::desde_json(&texto)?;
            let sk = clave::cargar(&clave, &pedir_contrasena(false)?)?;
            let evento = Evento {
                tipo,
                actor,
                identificacion,
                rol,
                fecha_utc: ahora_utc(),
                reloj: reloj.unwrap_or_else(|| RELOJ_SIN_VERIFICAR.into()),
                descripcion,
            };
            custodia::agregar(&mut cadena, evento, &sk)?;
            std::fs::write(&ruta, serde_json::to_vec_pretty(&cadena)?)?;
            println!(
                "Evento añadido: la cadena tiene ahora {} eslabones.",
                cadena.eslabones.len()
            );
            Ok(true)
        }
        Custodia::Sello { cadena: ruta, sello } => {
            let texto = std::fs::read_to_string(&ruta)
                .with_context(|| format!("leyendo la cadena {}", ruta.display()))?;
            let mut cadena = custodia::desde_json(&texto)?;
            let datos = custodia::sellar_final(&mut cadena, &sello)?;
            std::fs::write(&ruta, serde_json::to_vec_pretty(&cadena)?)?;
            let n = cadena.eslabones.len();
            println!(
                // Decía «desde ahora, entregar la cadena recortada por el final se
                // detecta al verificar», y prometía más que el README y más que el
                // propio verificador: quien recorta la cadena puede quitar también
                // el sello, y entonces se ve «sin sello», no «truncada». El sello
                // tiene que VIAJAR con la cadena o estar publicado. La séptima
                // revisión lo dejó como residual informativo; se cierra aquí porque
                // una herramienta que acredita no puede decir de más en su propia
                // salida. Es la misma regla que el documento: nada que no se pueda
                // sostener.
                "Sello de tiempo puesto sobre el eslabón {} (el último de {n}).\n  \
                 fecha cierta: {} — {}\n  \
                 Una cadena recortada por el final se detecta al verificar MIENTRAS el\n  \
                 sello llegue con ella: quien la recorta puede quitarlo también, y\n  \
                 entonces se verá «sin sello». Entrégalo junto a la cadena o publícalo.",
                n - 1,
                datos.fecha_utc,
                sello
            );
            Ok(true)
        }
        Custodia::Verificar { cadena: ruta, acta, tsa_ca } => {
            let texto = std::fs::read_to_string(&ruta)
                .with_context(|| format!("leyendo la cadena {}", ruta.display()))?;
            let cadena = custodia::desde_json(&texto)?;
            let anclas = leer_anclas(tsa_ca.as_deref())?;
            // El acta se ata por CONTENIDO (sus bytes canónicos) y por AUTOR (la
            // clave pública de su perito): las dos viven mientras dura el match.
            let acta_cargada = match &acta {
                Some(p) => Some(leer_acta(p)?),
                None => None,
            };
            let bytes = acta_cargada.as_ref().map(|a| a.bytes_canonicos());
            let ancla = match (&bytes, &acta_cargada) {
                (Some(b), Some(a)) => Some(custodia::Ancla {
                    bytes_canonicos: b,
                    clave_publica: &a.perito.clave_publica,
                }),
                _ => None,
            };
            match custodia::verificar(&cadena, ancla)? {
                custodia::Veredicto::Intacta => {
                    println!(
                        "✔ Cadena de custodia ÍNTEGRA: {} eslabones, firmas triple válidas, sin saltos ni reordenamientos.",
                        cadena.eslabones.len()
                    );
                    // Se acumula y se decide AL FINAL. El retorno temprano que
                    // puso la cuarta revisión se saltaba `estado_sello`, que es el
                    // único sitio que detecta TRUNCADA — y para entonces ya se
                    // había impreso «ÍNTEGRA». Quinta revisión.
                    let mut bien = true;
                    if let Some(a) = &acta_cargada {
                        // `custodia::verificar` solo compara la clave como CADENA y
                        // el hash canónico: no dice nada de si el acta está firmada
                        // ni de si su sello vale. Se comprueban LAS DOS COSAS, o
                        // este comando queda más permisivo que `tunjo verificar`
                        // sobre el mismo archivo.
                        match a.verificar_sello() {
                            Ok(()) => println!(
                                "  Y corresponde al acta, cuya firma SÍ verifica con la misma clave."
                            ),
                            Err(e) => {
                                println!(
                                    "  ✗ Corresponde a esa acta, pero LA FIRMA DEL ACTA NO VERIFICA: {}",
                                    informe::plano(&e.to_string())
                                );
                                println!(
                                    "    La cadena está íntegra sobre un acta que no acredita nada."
                                );
                                bien = false;
                            }
                        }
                        match a.verificar_sello_tiempo(&anclas) {
                            Ok(Some((_, c))) if c.acredita_autoridad() => {
                                println!("  El sello de tiempo del ACTA es válido y está anclado.");
                            }
                            Ok(Some(_)) => println!(
                                "  ⚠ El sello de tiempo del ACTA tiene firma válida pero SIN ANCLAR."
                            ),
                            Ok(None) => println!("  (El acta no lleva sello de tiempo propio.)"),
                            Err(e) => {
                                println!(
                                    "  ✗ EL SELLO DE TIEMPO DEL ACTA NO ES VÁLIDO: {}",
                                    informe::plano(&e.to_string())
                                );
                                bien = false;
                            }
                        }
                    } else {
                        println!("  (Sin --acta no se comprobó a qué acta pertenece ni quién la firmó.)");
                    }
                    println!(
                        "  Huella de la clave de la cadena (cotéjala con la del perito): {}",
                        huella_clave(&cadena.clave_publica)
                    );
                    // La integridad prueba un PREFIJO; el sello de tiempo dice si
                    // ese prefijo es TODO lo que hubo. Sin sello no se puede saber.
                    // El resultado se COMBINA con lo que dijo el acta: ninguna
                    // mitad puede tapar el fallo de la otra.
                    let sello_ok = match custodia::estado_sello(&cadena, &anclas) {
                        custodia::EstadoSello::Ausente => {
                            println!(
                                "  Sin sello de tiempo: prueba el orden relativo, no la fecha ni que\n  \
                                 no falten eventos AL FINAL. Séllala con `tunjo custodia sello`."
                            );
                            true
                        }
                        custodia::EstadoSello::Vigente { fecha_utc, secuencia, confianza } => {
                            if confianza.acredita_autoridad() {
                                println!(
                                    "  ✔ Sellada en el tiempo (RFC 3161) sobre el último eslabón ({secuencia}):\n  \
                                     fecha cierta {fecha_utc}, acreditada por {}.\n  \
                                     La cadena está completa hasta aquí.",
                                    confianza.autoridad()
                                );
                            } else {
                                // Sin ancla la firma es válida pero anónima, y NO se
                                // afirma completitud: un autofirmado llega hasta aquí.
                                println!(
                                    "  ⚠ Sello sobre el último eslabón ({secuencia}) con firma válida de\n  \
                                     «{}», fecha {fecha_utc} — pero SIN ANCLAR: no dijiste en qué\n  \
                                     autoridad confías, así que esa identidad no está acreditada y de\n  \
                                     esta cadena no se puede afirmar que esté completa.\n  \
                                     Exígelo con `--tsa-ca <raíz.pem>`.",
                                    confianza.autoridad()
                                );
                            }
                            true
                        }
                        custodia::EstadoSello::CubrePrefijo { fecha_utc, sellado, ultimo, confianza } => {
                            println!(
                                "  {} Sellada en el tiempo (RFC 3161) hasta el eslabón {sellado} ({fecha_utc});\n  \
                                 los eslabones {}..{ultimo} se añadieron después y aún no están sellados.{}",
                                if confianza.acredita_autoridad() { "✔" } else { "⚠" },
                                sellado + 1,
                                if confianza.acredita_autoridad() {
                                    String::new()
                                } else {
                                    format!(
                                        "\n  El sello lo firma «{}» y NO está anclado: esa identidad no\n  \
                                         está acreditada. Exígelo con `--tsa-ca <raíz.pem>`.",
                                        confianza.autoridad()
                                    )
                                }
                            );
                            true
                        }
                        custodia::EstadoSello::Truncada { fecha_utc, sellado, ultimo, confianza } => {
                            // Se delata igual con sello anclado o sin anclar: la cadena
                            // se contradice a sí misma, y eso no depende de la confianza.
                            println!(
                                "  ✗ TRUNCADA: hay un sello de tiempo ({fecha_utc}) sobre el eslabón {sellado},\n  \
                                 pero la cadena entregada llega solo al {ultimo}. Le quitaron eventos del final.\n  \
                                 Sello firmado por «{}»{}.",
                                confianza.autoridad(),
                                if confianza.acredita_autoridad() { ", anclado" } else { ", SIN anclar" }
                            );
                            false
                        }
                        custodia::EstadoSello::Invalido { motivo } => {
                            println!("  ✗ El sello de tiempo NO es válido: {motivo}.");
                            false
                        }
                    };
                    // `bien` viene del acta; `sello_ok`, de la cadena. Un fallo en
                    // cualquiera de los dos es un fallo del comando.
                    Ok(bien && sello_ok)
                }
                custodia::Veredicto::Rota { secuencia, motivo } => {
                    println!("✗ Cadena ROTA en el eslabón {secuencia}: {motivo}.");
                    Ok(false)
                }
                custodia::Veredicto::ActaNoCorresponde { esperado, encontrado } => {
                    println!(
                        "✗ La cadena es íntegra pero ancla OTRA acta.\n  \
                         esperado (acta dada): {}\n  ancla de la cadena:   {}",
                        informe::plano(&esperado),
                        informe::plano(&encontrado)
                    );
                    Ok(false)
                }
                custodia::Veredicto::FirmanteAjeno { esperado, encontrado } => {
                    println!(
                        "✗ La cadena es íntegra pero la firmó una clave que NO es la del perito del acta:\n  \
                         no la levantó quien selló la evidencia.\n  \
                         huella perito del acta: {}\n  huella firmante cadena: {}",
                        huella_clave(&esperado),
                        huella_clave(&encontrado)
                    );
                    Ok(false)
                }
                custodia::Veredicto::SinGenesis => {
                    // Las dos formas de no tener génesis se dicen distinto: una
                    // cadena vacía no atestigua nada, y una que arranca en el
                    // eslabón N oculta todo lo anterior a N.
                    let detalle = match cadena.eslabones.first() {
                        None => "está vacía: cero eslabones".to_string(),
                        Some(e) => format!("arranca en el eslabón {}, no en el 0", e.secuencia),
                    };
                    println!(
                        "✗ La cadena no arranca en el evento génesis ({detalle}):\n  \
                         no atestigua ninguna custodia."
                    );
                    Ok(false)
                }
            }
        }
    }
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
        Orden::Verificar { acta, origen, tsa_ca } => orden_verificar(acta, origen, tsa_ca),
        Orden::Acta { acta, salida, tsa_ca } => orden_acta(acta, salida, tsa_ca),
        Orden::Custodia { accion } => orden_custodia(accion),
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

// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! El sellado propiamente dicho.
//!
//! Vive aquí y no en `main` para que las pruebas ejerciten exactamente el mismo
//! camino que el CLI. Una prueba que reimplementa lo que verifica no prueba
//! nada: pasa por su propia lógica, no por la del programa.

use std::path::Path;

use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Local, SecondsFormat, Utc};
use quipu::pqsign::TripleSigningKey;

use crate::acta::{ALGORITMOS, Acta, Adquisicion, Caso, FORMATO, Firma, Perito, Reloj};
use crate::recoleccion;

/// Lo que el perito declara y la herramienta no puede deducir.
pub struct Datos {
    pub referencia: String,
    pub descripcion: String,
    pub perito: String,
    pub identificacion: String,
    pub metodo: String,
    /// Cómo se contrastó el reloj. `None` queda escrito como NO VERIFICADO: el
    /// acta nunca calla la ausencia de un dato ni la rellena con un supuesto.
    pub reloj: Option<String>,
    /// Permite sellar con elementos ilegibles, dejando constancia de cada uno.
    pub admitir_ilegibles: bool,
}

/// Recolecta, arma el acta, la firma y **comprueba el sello recién puesto**.
pub fn sellar(origen: &Path, sk: &TripleSigningKey, datos: &Datos) -> Result<Acta> {
    let inicio = Utc::now();
    let recogido = recoleccion::recolectar(origen)?;
    let fin = Utc::now();

    if recogido.elementos.is_empty() {
        bail!("{} no contiene ningún elemento: no hay nada que sellar", origen.display());
    }
    if !recogido.ilegibles.is_empty() && !datos.admitir_ilegibles {
        bail!(
            "no se pudieron leer {} elemento(s): {}. Sellado detenido: un acta que \
             calla lo que no pudo leer es un acta falsa. Si el material realmente es \
             ilegible, repite con --admitir-ilegibles y quedará constancia expresa.",
            recogido.ilegibles.len(),
            recogido.ilegibles.join("; ")
        );
    }

    let mut acta = Acta {
        formato: FORMATO.to_string(),
        caso: Caso {
            referencia: datos.referencia.clone(),
            descripcion: datos.descripcion.clone(),
        },
        perito: Perito {
            nombre: datos.perito.clone(),
            identificacion: datos.identificacion.clone(),
            clave_publica: STANDARD.encode(sk.verifying_key().to_bytes()),
        },
        adquisicion: Adquisicion {
            origen: origen.canonicalize()?.display().to_string(),
            metodo: datos.metodo.clone(),
            reloj: Reloj {
                inicio_utc: inicio.to_rfc3339_opts(SecondsFormat::Secs, true),
                fin_utc: fin.to_rfc3339_opts(SecondsFormat::Secs, true),
                desfase_local_utc: Local::now().offset().to_string(),
                verificacion: datos
                    .reloj
                    .clone()
                    .unwrap_or_else(|| "NO VERIFICADO contra fuente externa de tiempo".to_string()),
            },
            herramienta: crate::herramienta(),
            algoritmos: ALGORITMOS.to_string(),
        },
        elementos: recogido.elementos,
        raiz_merkle: String::new(),
        firma: None,
    };

    acta.fijar_raiz()?;
    let firma = sk.sign(&acta.bytes_canonicos());
    acta.firma = Some(Firma {
        algoritmo: ALGORITMOS.to_string(),
        valor: STANDARD.encode(&firma),
    });

    // Comprobar el sello ANTES de entregarlo. Un acta que no se verifica a sí
    // misma no debe salir de aquí: el sitio donde se descubriría es la audiencia.
    acta.verificar_sello()?;
    Ok(acta)
}

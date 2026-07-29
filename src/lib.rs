// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! **Tunjo** — sellado de evidencia digital y acta de cadena de custodia.
//!
//! Un *tunjo* es la figura de tumbaga con que los muiscas dejaban constancia
//! sellada de un acto. Esto hace lo mismo con bytes: dice qué había, cuándo se
//! recogió y quién responde, de forma que un tercero pueda comprobarlo sin
//! creerle a nadie.
//!
//! El sello usa la firma triple-híbrida de Quipu (Ed25519 + ML-DSA-87 +
//! SLH-DSA, las tres a la vez) por una razón que no es de moda criptográfica:
//! una prueba judicial tiene que seguir verificándose cuando el proceso llegue
//! a casación, y las firmas clásicas de hoy no tienen garantizada esa vida útil.

pub mod acta;
pub mod clave;
pub mod custodia;
pub mod informe;
pub mod merkle;
pub mod recoleccion;
pub mod sellado;
pub mod sello_tiempo;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Cómo se identifica la herramienta dentro del acta.
pub fn herramienta() -> String {
    format!("tunjo {VERSION} (sobre quipu, firma triple-híbrida)")
}

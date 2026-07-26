// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Árbol de Merkle sobre los elementos del acta.
//!
//! Se usa un árbol y no un hash único de la concatenación por una razón
//! práctica en juicio: permite probar que **un** archivo concreto estaba en la
//! adquisición sin revelar los demás. En un peritaje eso importa — la
//! contraparte tiene derecho a verificar el correo que la incrimina, no a leer
//! los otros 4.000 de la casilla.
//!
//! Separación de dominio en cada nivel (`0x00` hoja, `0x01` nodo interno) para
//! que ningún hash de hoja pueda hacerse pasar por un nodo interno. La raíz
//! final ata además el **número de elementos** (`0x02`), que cierra la
//! ambigüedad clásica de los árboles con número impar de hojas: sin eso, dos
//! conjuntos distintos pueden producir la misma raíz.

use sha2::{Digest, Sha256};

/// Hash de hoja: se calcula sobre la serialización canónica del elemento
/// completo, no solo sobre el contenido del archivo. Así la ruta, el tamaño y
/// el estado quedan atados igual que los bytes: mover un archivo de sitio
/// invalida el sello, que es justo lo que la cadena de custodia exige probar.
pub fn hoja(elemento_canonico: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update((elemento_canonico.len() as u64).to_be_bytes());
    h.update(elemento_canonico);
    h.finalize().into()
}

fn nodo(izq: &[u8; 32], der: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(izq);
    h.update(der);
    h.finalize().into()
}

/// Raíz del árbol. `None` si no hay elementos: un acta sin elementos no es un
/// acta vacía válida, es un error de operación, y quien llama debe tratarlo
/// como tal en vez de sellar la nada.
pub fn raiz(hojas: &[[u8; 32]]) -> Option<[u8; 32]> {
    if hojas.is_empty() {
        return None;
    }
    let n = hojas.len() as u64;
    let mut nivel: Vec<[u8; 32]> = hojas.to_vec();
    while nivel.len() > 1 {
        let mut siguiente = Vec::with_capacity(nivel.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < nivel.len() {
            siguiente.push(nodo(&nivel[i], &nivel[i + 1]));
            i += 2;
        }
        if i < nivel.len() {
            // Impar: el último sube tal cual. NO se duplica — duplicar permite
            // construir dos conjuntos distintos con la misma raíz.
            siguiente.push(nivel[i]);
        }
        nivel = siguiente;
    }
    // Ata el número de hojas: cierra la ambigüedad que deja la promoción.
    let mut h = Sha256::new();
    h.update([0x02]);
    h.update(n.to_be_bytes());
    h.update(nivel[0]);
    Some(h.finalize().into())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn hojas(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| hoja(format!("elemento {i}").as_bytes())).collect()
    }

    #[test]
    fn sin_elementos_no_hay_raiz() {
        assert_eq!(raiz(&[]), None);
    }

    #[test]
    fn una_hoja_tiene_raiz_distinta_de_la_hoja() {
        let h = hojas(1);
        // Si la raíz de un solo elemento fuera la hoja misma, un hash de hoja
        // podría presentarse como raíz de un acta.
        assert_ne!(raiz(&h).unwrap(), h[0]);
    }

    #[test]
    fn cambiar_un_elemento_cambia_la_raiz() {
        let a = hojas(7);
        let mut b = a.clone();
        b[3] = hoja(b"otra cosa");
        assert_ne!(raiz(&a), raiz(&b));
    }

    #[test]
    fn el_orden_importa() {
        let a = hojas(5);
        let mut b = a.clone();
        b.swap(0, 4);
        assert_ne!(raiz(&a), raiz(&b));
    }

    #[test]
    fn conjuntos_de_distinto_tamano_no_colisionan() {
        // El caso clásico: con promoción de impares y sin atar el número de
        // hojas, [a,b,c] y [a,b,c,c] podían compartir raíz.
        for n in 1..40usize {
            let r1 = raiz(&hojas(n)).unwrap();
            let mut mas = hojas(n);
            let ultima = *mas.last().unwrap();
            mas.push(ultima);
            assert_ne!(r1, raiz(&mas).unwrap(), "colisión con n={n}");
        }
    }

    #[test]
    fn la_raiz_es_estable() {
        // Misma entrada, misma raíz: el acta se verifica años después y en otra
        // máquina, así que esto no puede depender del entorno.
        let h = hojas(11);
        assert_eq!(raiz(&h), raiz(&h));
    }
}

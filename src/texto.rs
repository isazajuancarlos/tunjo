// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! El único sitio donde se neutraliza texto que no escribimos nosotros.
//!
//! # Por qué existe como módulo propio
//!
//! Vivía dentro de `informe`, que es el módulo del documento. Eso funcionaba
//! mientras el único texto ajeno viniera del acta, pero la verificación del sello
//! RFC 3161 trajo una fuente nueva —el certificado y el token de la autoridad— y
//! `firma_cms` no puede depender del generador de informes sin invertir las capas.
//! Está aquí para que lo use quien lo necesite sin arrastrar nada.
//!
//! # Y por qué se aplica en la CONSTRUCCIÓN, no en cada `println!`
//!
//! La séptima revisión de seguridad dejó una nota de endurecimiento: el sujeto del
//! certificado y el motivo de un sello inválido se imprimían en crudo en seis
//! sitios de `main.rs`, mientras el resto del texto ajeno pasaba por aquí. No era
//! explotable —el `Display` de `x509-cert` escapa los controles en hexadecimal
//! conforme a RFC 4514— pero la garantía dependía del `Display` de un tercero, y
//! eso es una invariante que no se puede leer en nuestro código.
//!
//! Arreglarlo poniendo seis llamadas más sería el método que este PR lleva seis
//! rondas demostrando que no converge: se acuerda uno de cinco y el sexto sale en
//! la ronda siguiente. Así que se neutraliza **donde el valor nace** —al construir
//! `Confianza`, `DatosSello` y el motivo de `EstadoSello::Invalido`— y a partir de
//! ahí no hay manera de imprimir un control desde ninguno de los tres, hoy ni
//! cuando alguien añada el séptimo sitio.

/// Aplana el texto para que pueda salir por una terminal sin reescribirla.
///
/// Todo carácter de control pasa a espacio. Es lo que hace falta y nada más: un
/// `\u{1b}[2K` dentro de un campo borra la línea que acaba de imprimirse y pinta
/// encima «SELLO VÁLIDO». El código de salida seguía siendo el correcto, pero nadie
/// frente a un prompt lo mira. Cuarta revisión de seguridad.
///
/// Para el documento Markdown esto NO basta —ahí hace falta escapar la puntuación,
/// que es lo que hace `informe::Dato`—; aquí se resuelve solo la pantalla.
pub fn plano(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn ningun_control_sobrevive() {
        let carga = "R-1\u{1b}[2K\u{1b}MSELLO VÁLIDO\n  perito: Otro\r\u{7}\t";
        let salida = plano(carga);
        assert!(
            !salida.chars().any(|c| c.is_control()),
            "sobrevivió un carácter de control: {salida:?}"
        );
        // Y no se come el texto legible, o estaría midiendo otra cosa.
        assert!(salida.contains("SELLO VÁLIDO"));
        assert!(salida.contains("perito: Otro"));
    }

    #[test]
    fn el_texto_normal_no_se_toca() {
        for s in [
            "CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1,O=DigiCert\\, Inc.,C=US",
            "2026-07-30T16:06:10Z",
            "cédula 1.020.304.050, folio 3º",
        ] {
            assert_eq!(plano(s), s, "se alteró texto que no había que tocar");
        }
    }
}

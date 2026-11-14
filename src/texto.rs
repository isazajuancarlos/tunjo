// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
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
    s.chars()
        .map(|c| if c.is_control() || es_formato_invisible(c) { ' ' } else { c })
        .collect()
}

/// Caracteres **invisibles o de formato bidireccional** que NO son de control
/// (`is_control()` no los ve, porque son categoría Unicode Cf, no Cc) y que en un
/// documento que lee un juez pueden **reordenar o esconder** texto sin que se note
/// — el ataque «Trojan Source» (U+202E y familia) y los de ancho cero.
///
/// Un nombre de archivo `factura\u{202E}gpj.exe` se ve «factura exe.jpg»; un
/// `fac\u{200B}tura` esconde un corte. En los CAMPOS del acta (método, fundamento,
/// rutas, perito) prima que no escondan ni reordenen nada —no son el contenido
/// sellado, que viaja como bytes con su hash—, así que se neutralizan a espacio,
/// igual que los controles. Los acentos del español (é, ñ, ü, º) y la demás
/// tipografía quedan fuera de estos rangos y no se tocan.
///
/// **Matiz honesto:** U+200C/U+200D (ZWNJ/ZWJ) SÍ son legítimos en escrituras no
/// latinas (persa, índicas) y en emoji; aquí se neutralizan igual, y el nombre real
/// del archivo lo ancla su `sha256` en el anexo — la pérdida es de legibilidad del
/// campo, no de prueba. Los selectores de variación (U+FE0F, Mn) se DEJAN fuera a
/// propósito: legítimos en emoji y no ocultan texto.
///
/// **Alcance y su límite (concilio 2026-10-12):** cubre el conjunto PELIGROSO
/// conocido de Unicode 16 (bidi, ancho cero, *tags* que ocultan texto, separadores
/// de línea/párrafo, formato deprecado). NO es la propiedad completa
/// `Default_Ignorable_Code_Point` (≈170 Cf): la forma robusta sería una tabla
/// generada de esa propiedad o un crate, decisión pendiente por la postura de
/// dependencia cero del repo.
///
/// Complementa, NO sustituye, al olfateador de ofuscación de `~/.claude/hooks`, que
/// AVISA de estos caracteres al LEERLOS; aquí se impide que salgan al acta.md.
pub fn es_formato_invisible(c: char) -> bool {
    matches!(c as u32,
        0x00AD                 // soft hyphen (guion discrecional, invisible)
        | 0x061C               // Arabic letter mark
        | 0x180E               // Mongolian vowel separator
        | 0x200B..=0x200F      // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | 0x2028..=0x2029      // separador de línea (Zl) y de párrafo (Zp)
        | 0x202A..=0x202E      // LRE, RLE, PDF, LRO, RLO (embeddings/overrides bidi)
        | 0x2060..=0x2064      // word joiner e invisibles matemáticos
        | 0x2066..=0x206F      // aislamientos bidi (2066-9) + formato deprecado (206A-F)
        | 0xFEFF               // BOM / zero-width no-break space
        | 0xFFF9..=0xFFFB      // anclas de anotación interlineal
        | 0xE0001              // language tag (deprecado)
        | 0xE0020..=0xE007F    // TAG characters: ocultan texto ASCII completo
    )
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
            // Acentos, eñe, diéresis y ordinales: fuera de los rangos de formato.
            "inspección extraprocesal, señor Núñez, ¿güiro? ¡sí!",
        ] {
            assert_eq!(plano(s), s, "se alteró texto que no había que tocar");
        }
    }

    #[test]
    fn ningun_formato_invisible_sobrevive() {
        // Trojan Source (RLO) + anchos cero + BOM + TAG (ASCII smuggling) + formato
        // deprecado, incrustados en un nombre y un campo: el ataque es que NO se ven.
        let carga = "factura\u{202E}gpj.exe  fac\u{200B}tura\u{FEFF} \u{2066}oc\u{E0041}ulto\u{2069} \u{206A}x\u{180E}";
        let salida = plano(carga);
        // NO-TAUTOLÓGICO: contra una lista LITERAL de peligrosos, independiente del
        // predicado. Si el predicado se olvidara de uno (p. ej. el tag), este `any`
        // seguiría en verde pero este `contains` lo cazaría.
        for peligroso in ['\u{202E}', '\u{200B}', '\u{FEFF}', '\u{2066}', '\u{2069}', '\u{E0041}', '\u{206A}', '\u{180E}'] {
            assert!(!salida.contains(peligroso), "sobrevivió U+{:04X}: {salida:?}", peligroso as u32);
        }
        // Y el predicado reconoce uno a uno el conjunto (incluidos los nuevos).
        for c in ['\u{202E}', '\u{200B}', '\u{200D}', '\u{FEFF}', '\u{2066}', '\u{00AD}',
                  '\u{E0041}', '\u{E0001}', '\u{206A}', '\u{206F}', '\u{180E}', '\u{2028}', '\u{2029}'] {
            assert!(es_formato_invisible(c), "no reconoció U+{:04X}", c as u32);
        }
        // Y NO marca texto legítimo (incluida la é, que está pegada en la carga)…
        for c in ['a', 'é', 'ñ', 'ü', '3', '.', ' ', 'º'] {
            assert!(!es_formato_invisible(c), "marcó como invisible U+{:04X}", c as u32);
        }
        // …ni los BORDES justo fuera de cada rango: un mutante que ensanche un rango
        // (p. ej. 2066..=2070) se pone rojo aquí (el lado ciego de D33, cerrado).
        for c in ['\u{2027}', '\u{202F}', '\u{2065}', '\u{2070}', '\u{180F}', '\u{E0000}', '\u{E0080}'] {
            assert!(!es_formato_invisible(c), "ensanchó un rango hasta U+{:04X}", c as u32);
        }
    }
}

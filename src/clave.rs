// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
// SPDX-License-Identifier: AGPL-3.0-or-later
//! La clave del perito.
//!
//! Se guarda cifrada con el propio contenedor de Quipu (Argon2id +
//! ChaCha20-Poly1305). Una clave de firma forense en claro sobre el disco es
//! la primera cosa que la contraparte usaría para negar la autoría del acta:
//! si cualquiera con acceso al portátil pudo firmar, el sello no prueba quién.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use quipu::api::{Options, decode_from_blob, encode_to_blob};
use quipu::pqsign::{TripleSigningKey, TripleVerifyingKey, generate_triple_keypair};

/// Marca del archivo de clave. Sale como huella del codebook, así que un
/// archivo que no sea una clave de tunjo falla antes de pedir la contraseña.
const HUELLA: [u8; 8] = *b"TUNJOKEY";

/// Genera un par nuevo y deja la clave privada cifrada en `ruta`.
pub fn generar(ruta: &Path, passphrase: &str) -> Result<TripleVerifyingKey> {
    if ruta.exists() {
        // Sobrescribir una clave de firma es irreversible y deja sin verificar
        // todas las actas firmadas con ella. No se hace nunca en silencio.
        bail!(
            "ya existe {} — no se sobrescribe una clave de firma: las actas \
             firmadas con ella quedarían sin poder verificarse",
            ruta.display()
        );
    }
    let (vk, sk) = generate_triple_keypair();
    let blob = encode_to_blob(&sk.to_bytes(), passphrase, HUELLA, &Options::default());
    fs::write(ruta, &blob).with_context(|| format!("escribiendo {}", ruta.display()))?;
    restringir_permisos(ruta)?;
    Ok(vk)
}

/// Carga y descifra la clave de firma.
pub fn cargar(ruta: &Path, passphrase: &str) -> Result<TripleSigningKey> {
    let blob = fs::read(ruta).with_context(|| format!("leyendo {}", ruta.display()))?;
    let bytes = decode_from_blob(&blob, passphrase, HUELLA, b"").map_err(|e| motivo(e, ruta))?;
    TripleSigningKey::from_bytes(&bytes)
        .ok_or_else(|| anyhow::anyhow!("el archivo no contiene una clave de firma triple válida"))
}

/// Traduce el fallo del contenedor al motivo REAL, que no siempre es la
/// contraseña.
///
/// Hasta el 2026-08-04 todo error de `decode_from_blob` salía como
/// «no se pudo abrir la clave (…): ¿contraseña correcta?». A quien apuntaba al
/// archivo equivocado —lo más fácil de hacer con `--ruta`— se le mandaba a
/// revisar una contraseña que estaba bien, y el contenedor ni siquiera había
/// llegado a probarla: `CodebookMismatch` se decide comparando la huella de la
/// cabecera, ANTES del KDF. Es la misma regla que el resto de la herramienta:
/// no se afirma lo que no se comprobó.
///
/// El `match` es exhaustivo a propósito, sin brazo comodín: si Quipu añade una
/// variante, esto deja de compilar en vez de heredar un mensaje que miente.
fn motivo(e: quipu::api::DecodeError, ruta: &Path) -> anyhow::Error {
    use quipu::api::DecodeError as D;
    use quipu::container::ContainerError as C;

    let r = ruta.display();
    match e {
        D::Container(C::TooShort | C::BadMagic) => anyhow::anyhow!(
            "{r} no es una clave de tunjo: no lleva la cabecera del contenedor \
             cifrado. La contraseña no se llegó a probar — comprueba la ruta"
        ),
        D::Container(C::UnsupportedVersion(v)) => anyhow::anyhow!(
            "{r} usa la versión {v} del contenedor y esta copia de tunjo no la \
             conoce. Hace falta una versión más nueva: no se intenta adivinar el \
             formato"
        ),
        D::Container(C::FlagsDesconocidos(f)) => anyhow::anyhow!(
            "{r} trae marcas de formato que esta copia de tunjo no conoce \
             ({f:#010b}). Se rechaza en vez de interpretarlo con las reglas \
             viejas, que daría un resultado mal leído con el cifrado en verde"
        ),
        D::CodebookMismatch => anyhow::anyhow!(
            "{r} es un contenedor cifrado de Quipu, pero NO una clave de tunjo: \
             le falta la marca {}. La contraseña no se llegó a probar",
            String::from_utf8_lossy(&HUELLA)
        ),
        D::Decrypt => anyhow::anyhow!(
            "no se pudo descifrar {r}: la contraseña es incorrecta, o el archivo \
             fue alterado. Las dos cosas fallan igual y desde aquí no se pueden \
             distinguir"
        ),
        // Los dos caminos del diccionario y de la firma no los recorre una clave
        // de perito, que va por blob y por contraseña. Si aparecen, lo honrado es
        // decir que no sabemos, no elegir la explicación más cómoda.
        e @ (D::Symbol(_) | D::BadSignature) => anyhow::anyhow!(
            "{r} falló al abrirse con un error que este camino no debería \
             producir ({e:?}); no se interpreta"
        ),
    }
}

#[cfg(unix)]
fn restringir_permisos(ruta: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(ruta, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restringir_permisos(_ruta: &Path) -> Result<()> {
    // En Windows el archivo hereda la ACL del directorio del usuario. El
    // cifrado del contenedor es lo que protege la clave, no los permisos.
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Un `.clave` REAL generado el 2026-08-05 con quipu 0.10.0, en base64.
    /// No se regenera: ese es el punto.
    const CLAVE_2026: &str = "\
        UVVJUAEAAABUVU5KT0tFWUA/+ZpR6d66bAvTLr/xrw3/pfDMWJ+yyS5kJwaE6DX6xHAj8e6fTuMA\
        AQAAAAAAAwAAAAGZrrVXgMy1Hia5E4nudX+i8c9GMx7SN10BP1gxEFC8VgnIPiDueda2lUk8YmJa\
        WE9ZdnGpQCsqmc9Ufsgi8eJ1QL1CQD3Zay11lejJufXpVkHmiUQni9BpKgKPFoeml8TpzwlS/uMr\
        WucjEWapCt3mpjssX7mUTwbImQrM5mHLSvVbzIBPcnWtoulIPOyg1ByOJclxbEnTG6XjGZd0I+B6\
        saXxmdQ1lzGqtlQW/UaFC9WMeDuwKZ2M7NNeG7wx0LkHc3lpunrR5MZfszohd3PF5ymJBd9IF0pg\
        Z5gkCqpb0A==";
    const FRASE_2026: &str = "contrasena-de-prueba-larga-2026";
    /// sha256 del TEXTO base64 de esa misma clave pública, medido el 2026-08-06
    /// con base64 0.23.0. Es el vector de la dirección ENCODE: cambia con un solo
    /// símbolo del alfabeto o un `=` de relleno de más.
    const HUELLA_B64_2026: &str =
        "497fcc3aac97a252ced427af5a47ed0e0624df23e2933c39a8a87eff5bbd842d";

    /// sha256 de `verifying_key().to_bytes()` de esa clave, medido con quipu
    /// 0.10.0 el 2026-08-05.
    const PUBLICA_2026: &str =
        "9c0f277bf06693dbe5d9a926bc14664d0e46c317ea99647ac4bb52bcc20cc451";

    fn clave_de_2026(dir: &std::path::Path) -> std::path::PathBuf {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let ruta = dir.join("de_2026.clave");
        fs::write(&ruta, STANDARD.decode(CLAVE_2026).expect("base64 del vector")).unwrap();
        ruta
    }

    fn huella_publica(sk: &TripleSigningKey) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(sk.verifying_key().to_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// **El vector fijo, y por qué las once pruebas de abajo no bastan.**
    ///
    /// Todas las demás generan el `.clave` y lo leen con el MISMO binario: miden
    /// el códec contra sí mismo y pasarían en verde aunque el formato del
    /// contenedor cambiara. Esta compara contra un archivo que YA existía.
    ///
    /// Lo que hay detrás no es estilo: de la clave del perito cuelga la firma de
    /// todas las actas emitidas. Si `encode_to_blob`/`decode_from_blob` movieran
    /// el formato o la derivación, los `.clave` en manos de peritos dejarían de
    /// abrirse **y ninguna prueba de este archivo lo diría**.
    ///
    /// Si se pone roja al subir `quipu`, NO se regenera el literal: significa
    /// que las claves emitidas hasta hoy dejaron de abrirse, y eso se decide, no
    /// se tapa. Es la PUERTA de la regla «tunjo va siempre a la Quipu actual».
    ///
    /// Comprobada contra los dos artefactos el 2026-08-05: quipu **0.10.0** y
    /// **0.11.0** devuelven esta misma huella.
    #[test]
    fn una_clave_de_2026_sigue_abriendo() {
        let dir = tempfile::tempdir().unwrap();
        let sk = cargar(&clave_de_2026(dir.path()), FRASE_2026)
            .expect("el .clave de 2026-08-05 dejó de abrirse");
        assert_eq!(
            huella_publica(&sk),
            PUBLICA_2026,
            "abre, pero devuelve OTRA clave: las actas firmadas ya no verifican"
        );
    }

    /// **EL VECTOR EN LA DIRECCIÓN CONTRARIA: que `encode` siga produciendo lo
    /// mismo.**
    ///
    /// `una_clave_de_2026_sigue_abriendo` cubre DECODIFICAR —lee un `.clave`
    /// literal de 2026 y comprueba la clave que sale—, y eso deja la otra mitad
    /// sin nadie: el resto del banco codifica y decodifica con el MISMO binario,
    /// así que pasa igual si el formato de SALIDA cambia.
    ///
    /// Y esa mitad decide algo. `custodia.rs:310` compara
    /// `cadena.clave_publica != ancla.clave_publica` **como TEXTO** para
    /// dictaminar `Veredicto::FirmanteAjeno`. Si el relleno o el alfabeto de
    /// salida se movieran, un acta sellada por un binario viejo daría
    /// `FirmanteAjeno` ESPURIO contra una cadena sellada por uno nuevo — un
    /// peritaje que se declara falso sin que nada esté mal. La verificación de
    /// firmas no corre ese riesgo (va siempre contra el texto ALMACENADO, no
    /// contra una recodificación), pero la identidad del perito sí.
    ///
    /// Lo levantó la revisión de seguridad del bump de base64 a 0.23 el
    /// 2026-08-06: el formato no se movió —1 202 vectores comprobados contra las
    /// dos versiones, 0 diferencias— pero nada en este repositorio lo sujetaba.
    ///
    /// Los bytes son fijos y elegidos para que el vector muerda: incluyen el
    /// caso de relleno (`len % 3 == 1` y `== 2`), y los valores 62 y 63, que son
    /// los dos únicos símbolos donde `STANDARD` (`+/`) y `URL_SAFE` (`-_`)
    /// difieren.
    #[test]
    fn codificar_en_base64_sigue_dando_lo_mismo() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        // 62 y 63 salen de estos tres bytes: 0xFB 0xEF 0xBE -> "++++"... se
        // comprueba abajo con el literal, que es lo que manda.
        const CASOS: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"t", "dA=="),                       // relleno de dos
            (b"tu", "dHU="),                      // relleno de uno
            (b"tunjo", "dHVuam8="),
            (&[0xFB, 0xEF, 0xBE], "++++"),        // los símbolos 62 y 63 de STANDARD
            (&[0xFF, 0xFF, 0xFF], "////"),
            (&[0x00, 0x00, 0x00], "AAAA"),
        ];
        for (bytes, esperado) in CASOS {
            assert_eq!(
                &STANDARD.encode(bytes),
                esperado,
                "`STANDARD.encode` cambió de formato. `custodia.rs:310` compara la \
                 clave pública COMO TEXTO para decidir `FirmanteAjeno`: con el \
                 formato movido, un acta vieja y una cadena nueva del MISMO perito \
                 dejan de corresponder. NO se regenera este literal sin decidir qué \
                 pasa con los peritajes ya sellados."
            );
        }
    }

    /// La pareja del anterior: una clave pública REAL, codificada como la
    /// codifica `firmante`, tiene que dar exactamente esta cadena.
    ///
    /// Los siete casos de arriba son sintéticos y podrían pasar con un códec
    /// correcto sobre el alfabeto equivocado si alguien cambiara la constante que
    /// usa `custodia`. Éste va contra el ARTEFACTO: la misma clave del vector de
    /// 2026, por la misma vía que `custodia::firmante`.
    #[test]
    fn la_clave_publica_del_perito_de_2026_se_codifica_igual() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let dir = tempfile::tempdir().unwrap();
        let sk = cargar(&clave_de_2026(dir.path()), FRASE_2026).unwrap();
        let publica = STANDARD.encode(sk.verifying_key().to_bytes());
        // Se compara el SHA-256 del TEXTO base64, no el texto: la clave triple
        // híbrida son ~4 KB codificados y pegarlos aquí no lo leería nadie. El
        // hash es igual de sensible al formato —cambia con un solo símbolo o un
        // `=` de más— y cabe en una línea.
        let huella: String = {
            use sha2::{Digest, Sha256};
            Sha256::digest(publica.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
        };

        // Medido el 2026-08-06 con base64 0.23.0 sobre el `.clave` de 2026-08-05.
        assert_eq!(
            huella, HUELLA_B64_2026,
            "la clave pública del perito de 2026 se codifica distinto: \
             `custodia.rs:310` la compara como texto y el acta dejaría de \
             corresponder con su cadena"
        );
    }

    /// La pareja del vector, y falla POR LA VÍA REAL: la contraseña equivocada
    /// sobre el MISMO archivo. No se voltea un byte del literal —eso solo
    /// probaría que la prueba sabe decodificar base64—; se cambia la entrada
    /// como la cambiaría un error de verdad.
    ///
    /// **El aserto casa contra «contraseña es incorrecta», no contra
    /// «contraseña» a secas, y la diferencia la midió una revisión.** Con el
    /// aserto laxo esta prueba se quedaba VERDE bajo el mutante de `HUELLA`:
    /// el mensaje de `CodebookMismatch` contiene la frase «La contraseña no se
    /// llegó a probar», que dice literalmente lo CONTRARIO de lo que esta
    /// prueba afirma medir y aun así la satisfacía. Una pareja que no
    /// discrimina no valida nada, y encima da la confianza de haberlo hecho.
    #[test]
    fn el_vector_no_abre_con_otra_contrasena() {
        let dir = tempfile::tempdir().unwrap();
        let r = cargar(&clave_de_2026(dir.path()), "otra-contrasena-igual-de-larga");
        assert!(
            error_de(r).contains("contraseña es incorrecta"),
            "una contraseña equivocada sobre el vector no culpó a la contraseña"
        );
    }

    /// El control de que la huella DISCRIMINA. Sin él, un `huella_publica` que
    /// devolviera una constante pasaría el vector de arriba y no mediría nada.
    #[test]
    fn la_huella_distingue_dos_claves() {
        let dir = tempfile::tempdir().unwrap();
        let otra = dir.path().join("otra.clave");
        generar(&otra, FRASE_2026).unwrap();
        let sk = cargar(&otra, FRASE_2026).unwrap();
        assert_ne!(
            huella_publica(&sk),
            PUBLICA_2026,
            "dos claves distintas dan la misma huella: el vector no mide nada"
        );
    }

    #[test]
    fn ciclo_completo_de_clave() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        let vk = generar(&ruta, "contraseña larga de prueba").unwrap();
        let sk = cargar(&ruta, "contraseña larga de prueba").unwrap();
        let firma = sk.sign(b"acta");
        assert!(vk.verify(b"acta", &firma));
        assert_eq!(sk.verifying_key().to_bytes(), vk.to_bytes());

        // Y el coste del KDF con el que se ESCRIBE una clave nueva. El vector
        // fijo ancla el DESCIFRADO y es ciego a esto por construcción:
        // `decode_from_blob` toma los parámetros de la cabecera del blob
        // GUARDADO, no de `Options`. Sin este aserto, una versión futura de
        // quipu que bajara el defecto haría cada `.clave` NUEVO más barato de
        // romper y las once pruebas seguirían en verde.
        //
        // Se pregunta a la API pública y no se parsea la cabecera contando
        // bytes: el primer intento lo hizo así, se equivocó de desplazamiento y
        // habría quedado atado a un formato que no es nuestro.
        let kdf = quipu::kdf::KdfParams::default();
        assert_eq!(
            (kdf.mem_kib, kdf.iterations, kdf.parallelism),
            (65536, 3, 1),
            "el KDF por defecto de quipu cambió: cada .clave nuevo se escribe \
             con otro coste, y el vector fijo NO lo ve"
        );

        // 0o600 en el archivo de clave. `restringir_permisos` no tenía una sola
        // prueba: borrarlo dejaba la suite entera en verde.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let modo = fs::metadata(&ruta).unwrap().permissions().mode() & 0o777;
            assert_eq!(modo, 0o600, "la clave privada quedó legible por otros");
        }
    }

    #[test]
    fn contrasena_equivocada_no_abre_la_clave() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        generar(&ruta, "la buena").unwrap();
        assert!(cargar(&ruta, "la mala").is_err());
    }

    // Los tres de abajo van juntos y se validan entre sí: dos que NO pueden
    // culpar a la contraseña y uno que TIENE que culparla. Con los primeros
    // solos pasaría igual un mensaje que nunca la nombra; con el último solo,
    // el que la nombra siempre —que es justo el que había hasta hoy—.

    /// El mensaje de un `cargar` que debía fallar.
    ///
    /// No se usa `unwrap_err()` porque exige `Debug` en el lado bueno, y
    /// `TripleSigningKey` no lo implementa a propósito: una clave privada no
    /// tiene por qué poder imprimirse. La prueba se adapta al tipo, no al revés.
    fn error_de(r: Result<TripleSigningKey>) -> String {
        match r {
            Ok(_) => panic!("esto tenía que fallar y abrió la clave"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn un_archivo_que_no_es_contenedor_no_culpa_a_la_contrasena() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("cualquiera.bin");
        fs::write(&ruta, [0xAB; 4096]).unwrap();

        let e = error_de(cargar(&ruta, "da igual"));
        assert!(e.contains("no es una clave de tunjo"), "{e}");
        assert!(
            !e.contains("contraseña es incorrecta"),
            "no se puede mandar a revisar la contraseña: ni se probó — {e}"
        );
    }

    #[test]
    fn un_contenedor_de_quipu_que_no_es_clave_de_tunjo_se_distingue() {
        // La pareja exacta del anterior: contenedor BIEN FORMADO, con su
        // cabecera y su cifrado, del que solo cambia la marca. Si el mensaje se
        // apoyara en la forma del archivo y no en la huella, aquí se caería.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("otro.blob");
        let ajena = *b"OTRACOSA";
        assert_ne!(ajena, HUELLA, "la marca ajena tiene que ser distinta");
        let blob = encode_to_blob(b"contenido cualquiera", "la buena", ajena, &Options::default());
        fs::write(&ruta, &blob).unwrap();

        let e = error_de(cargar(&ruta, "la buena"));
        assert!(e.contains("NO una clave de tunjo"), "{e}");
        // Contra la CONSTANTE, no contra una copia del texto: con el literal
        // pegado, esta prueba se caía al renombrar la marca —un cambio
        // legítimo— y se arreglaba editando el test, que es justo lo que el
        // CLAUDE.md prohíbe en su sección de pruebas.
        let marca = String::from_utf8_lossy(&HUELLA).to_string();
        assert!(e.contains(&marca), "dice qué marca falta — {e}");
        assert!(
            !e.contains("contraseña es incorrecta"),
            "la contraseña era la BUENA y ni se llegó a probar — {e}"
        );
    }

    #[test]
    fn la_contrasena_equivocada_si_nombra_la_contrasena() {
        // El control positivo. Sin él, «no culpa a la contraseña» lo cumpliría
        // un mensaje que no la nombra nunca, y el caso real quedaría mudo.
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        generar(&ruta, "la buena").unwrap();

        let e = error_de(cargar(&ruta, "la mala"));
        assert!(e.contains("contraseña es incorrecta"), "{e}");
        assert!(
            e.contains("alterado"),
            "y no se afirma cuál de las dos fue: desde aquí no se distinguen — {e}"
        );
    }

    #[test]
    fn no_se_sobrescribe_una_clave_existente() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        generar(&ruta, "una").unwrap();
        let antes = fs::read(&ruta).unwrap();
        assert!(generar(&ruta, "otra").is_err());
        assert_eq!(antes, fs::read(&ruta).unwrap(), "la clave original se conserva intacta");
    }

    #[test]
    fn la_clave_no_queda_en_claro_en_el_archivo() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = dir.path().join("perito.clave");
        generar(&ruta, "contraseña").unwrap();
        let sk = cargar(&ruta, "contraseña").unwrap();
        let en_disco = fs::read(&ruta).unwrap();
        let secreto = sk.to_bytes();
        assert!(
            !en_disco.windows(secreto.len()).any(|v| v == secreto.as_slice()),
            "el material secreto aparece literalmente en el archivo"
        );
    }
}

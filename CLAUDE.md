# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Configuración general: `~/.claude/CLAUDE.md`** (reglas, directivas numeradas,
> hooks y permisos). Se carga en toda sesión y **no se copia aquí**; este archivo
> lleva SOLO lo de tunjo. El inventario está en `/mnt/data/conocimiento/MAPA.md`.
>
> **Tunjo se lleva desde SU carpeta**: `cd /mnt/data/tunjo && claude`
> (autorización de Juan, 2026-08-03). Hasta esa fecha era uno de los cuatro
> repositorios que compartían el `CLAUDE.md` de decod; se separó para manejar
> cada proyecto por su cuenta **aunque sea un derivado**. De `decod/CLAUDE.md`
> solo hace falta lo de «Quién consume Quipu» cuando se vaya a subir una versión;
> lo demás de allí es de Quipu, no de aquí.

Tunjo sella evidencia digital y levanta el acta de cadena de custodia, con firma
triple-híbrida (Ed25519 + ML-DSA-87 + SLH-DSA) tomada de Quipu. AGPL-3.0-or-later,
`publish = false` —depende de `guaca` por git, y crates.io no admite deps git; y es
una app de peritaje, no una librería—.

## De dónde viene lo que consume

| Dependencia | Cómo entra | Por qué así |
|---|---|---|
| `quipu = "0.10"` (feature `slh`) | **crates.io**, nunca por `path` | un repositorio que solo compila con un checkout hermano no lo puede construir quien lo clona, y **el verificador tiene que ser ejecutable por cualquiera** |
| `guaca` (`auditoria`) | **git, fijado por `rev`** (= tag `v0.3.0`) | un tag es mutable: mover `v0.3.0` a un commit malicioso nos lo traería al construir (ataque Atomic Arch a AUR). El `Cargo.lock` ya lo fijaba; el `rev` lo hace explícito |

**Un cambio en Quipu o en guaca NO llega solo.** El árbol de decod va por
`0.11.0` y aquí se pide `^0.10`, que **no casa con 0.11**: publicar una versión
nueva de Quipu no actualiza a tunjo, y subir el requisito es una decisión que se
toma leyendo qué cambió (`/mnt/data/decod/CLAUDE.md`), no un `cargo update`. Lo
mismo con guaca: hasta que no se mueva el `rev`, aquí no entra nada.

## Comandos

```bash
# Los DOS del CI, exactos (.github/workflows/ci.yml). Verde local = estos dos.
cargo clippy --all-targets --release -- -D warnings
cargo test --release

cargo test --release --no-fail-fast          # para VER todos los fallos: sin esto
                                             # el primer binario rojo aborta el resto
cargo test --release --test integracion sellar_y_verificar_un_directorio  # una sola
cargo deny check                             # cadena de suministro (cargo install cargo-deny --locked)
```

**`--release` no es una preferencia, es la única forma viable.** SLH-DSA y Argon2id
sin optimizar tardan cerca de un minuto por operación; en `dev` la suite pasaba de
120 s solo en `sellado_concurrente_sin_interbloqueo` y se acusaba a sí misma de
interbloqueo. Por eso `[profile.dev.package."*"] opt-level = 3` optimiza las
*dependencias* y deja el crate propio depurable.

La única prueba que toca la red es opt-in y va marcada `#[ignore]`:

```bash
TUNJO_TSA=http://timestamp.digicert.com cargo test --release --test sello_tiempo -- --ignored
```

Para desarrollar contra un Quipu local (por defecto viene de crates.io, a
propósito: un repositorio que solo compila con un checkout hermano no lo puede
construir quien lo clona, y el verificador tiene que ser ejecutable por
cualquiera), un `.cargo/config.toml` sin versionar:

```toml
[patch.crates-io]
quipu = { path = "../decod" }
```

`guaca` va por **`rev` inmutable**, nunca por tag: mover `v0.3.0` a un commit
malicioso nos lo traería al construir.

## La arquitectura, en dos artefactos

| Artefacto | Qué prueba | Dónde vive |
|---|---|---|
| `acta.json` | un **instante**: estos bytes existían en T0, con esta raíz Merkle, firmados | `acta.rs`, `sellado.rs`, `recoleccion.rs`, `merkle.rs` |
| `cadena.json` | la **secuencia** ininterrumpida de quién la tuvo y qué hizo | `custodia.rs` (sobre `guaca::auditoria`) |

La cadena **no toca el acta**: se ancla a ella por el SHA-256 de sus
`bytes_canonicos()` y por la clave pública del perito, firmados en el evento
génesis. Las actas ya selladas siguen verificando idénticas.

El flujo: `recoleccion` recorre el origen en solo lectura → `merkle` arma la raíz →
`acta` la fija y `sellado` firma → opcionalmente `sello_tiempo` pide un token
RFC 3161 sobre **la firma** (no sobre el acta) → `firma_cms` verifica ese token →
`informe` produce el Markdown que se anexa al dictamen.

`sello_tiempo` y `firma_cms` están separados a propósito: el primero es el
protocolo (pedir, leer el `TSTInfo`, comprobar QUÉ sella); el segundo es la firma
CMS (QUIÉN lo firmó, si el certificado sirve para sellar, si estaba vigente, y si
encadena a un ancla aportada con `--tsa-ca`).

## Invariantes que no se pueden romper

Nacieron de siete pasadas de `security-review` sobre la rama del sello (2, 2, 3, 5,
6 y 9 defectos, el ritmo **subiendo**), y veintidós de veintisiete estaban en la
capa que reporta. Parchear caso por caso no convergía —dos defectos de la quinta
ronda los causaron los arreglos de la cuarta—, así que las dos clases de fallo se
hicieron **inexpresables**. Al tocar esta capa, se respetan o se vuelve al bucle:

1. **Ninguna afirmación sin su comprobación en el TIPO.** En `informe`, la prosa
   entra como `Fijo`/`Segun<C>`/`PorFecha`, constantes todas declaradas en el
   módulo `dicho`; `Documento` **no acepta ningún `&str`** (su `String` es privado
   del submódulo `papel`). Un `Segun<C>` obliga a escribir las DOS versiones —la
   que se dice cuando la comprobación salió bien y la que se dice cuando no—:
   callar no es una opción, porque un acta que no verifica es justo la que alguien
   querría presentar como buena. Donde la decisión no es binaria (`enum Fecha`) se
   despacha con `match` exhaustivo: **un estado nuevo sin su texto no compila.**
2. **Nada del JSON llega a la salida sin neutralizar.** Para el documento, `Dato`
   (escapa TODA la puntuación ASCII, no una lista negra) y `EnValla` (solo valores
   cuya forma se validó). Para la pantalla, `texto::plano` —y se aplica **donde el
   valor nace**: al construir `Confianza`, `DatosSello` y `EstadoSello::Invalido`,
   no en cada `println!`, porque acordarse en cada sitio es exactamente lo que
   falló seis rondas seguidas.
3. **Los tres comandos que verifican no se contradicen.** `verificar`, `acta` y
   `custodia verificar` devuelven el mismo veredicto sobre el mismo archivo: si uno
   es más permisivo, es el que recomendaría quien entrega algo forjado. Lo fija
   `tests/veredictos.rs`, que ejerce el **binario** y sus códigos de salida.
4. **Códigos de salida: `0` conforme, `1` la verificación falló, `2` error de
   operación.** Son API; un guion de revisión los distingue.
5. **Sin `--tsa-ca` no se dice «fecha cierta».** La firma del token se comprueba
   siempre, pero un autofirmado con el uso `id-kp-timeStamping` pasa toda la
   comprobación criptográfica: sin ancla, `Confianza::SinAnclar` y la salida lo
   advierte. No hay lista de confianza por defecto, a propósito.
6. **`verificar_sello()` comprueba en ESE orden**: formato → elemento «leido» sin
   huella → raíz **recalculada** → firma triple. Verificar solo la firma dejaría
   pasar un acta cuya raíz miente, porque la firma cubre el JSON entero, raíz
   incluida.
7. **`bytes_canonicos()` excluye `firma` y `sello_tiempo`**, y su determinismo
   depende de que `serde_json` respete el orden de declaración de los campos: **no
   se introducen mapas desordenados** en las structs del acta ni de la cadena.
8. **Merkle con separación de dominio** (`0x00` hoja, `0x01` nodo) y la raíz atando
   el **número de hojas** (`0x02`). Los impares **suben tal cual, no se duplican**:
   duplicar permite dos conjuntos distintos con la misma raíz.
9. **La herramienta acredita, no concluye**, y es firma **electrónica** del Decreto
   2364 de 2012, nunca «firma digital» del art. 28 de la Ley 527. Ninguna frase de
   la salida puede prometer más que el README (`MARCO_JURIDICO.md` §4 y §6.1).
10. **Nunca se escribe dentro del origen**, y `sellar` / `custodia iniciar` se
    niegan a sobrescribir su salida.

## Pruebas

Cinco binarios, cada uno con un encargo distinto: `integracion` (punta a punta por
el mismo camino del CLI, con la simulación de 240 contrastes y la de concurrencia),
`veredictos` (el **artefacto** y los códigos de salida, ejerciendo el binario),
`sello_tiempo` y `firma_cms` (sobre el token REAL de DigiCert en
`tests/fijos/sello_digicert.tsr` — un banco que solo prueba datos fabricados por
uno mismo no descubre las diferencias entre autoridades), y `cadena_suministro`
(guarda la única exención de `cargo-deny`, RUSTSEC-2023-0071, y se pone roja el día
que tunjo tenga una clave privada RSA).

Cada prueba de detección lleva su contraparte: se altera UNA cosa y se exige que
señale esa y **solo** esa. Y las pruebas del documento casan contra las
**constantes** de `dicho`, no contra copias del texto: una copia se pone verde para
siempre en cuanto alguien reflúa el párrafo.

## Convenciones

Todo en español —identificadores, pruebas, documentación— y los comentarios
explican **por qué**, con frecuencia nombrando la ronda de revisión que encontró el
defecto. Esa historia es la justificación de diseños que de otro modo parecen
recargados: no se borra al refactorizar.

`.gitignore` mantiene fuera `*.clave`, `acta*.json`, `acta*.md`, `/casos/` y
`/evidencia/`: **material de casos y claves nunca entran al repositorio.**

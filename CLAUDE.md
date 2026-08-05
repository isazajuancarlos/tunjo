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
| `quipu = "0.11"` (feature `slh`) | **crates.io**, nunca por `path` | un repositorio que solo compila con un checkout hermano no lo puede construir quien lo clona, y **el verificador tiene que ser ejecutable por cualquiera** |
| ↳ y va **SIEMPRE a la Quipu actual** | regla de la familia, **2026-08-05** | ver abajo — con su PUERTA, que es lo que la separa de la inercia |
| `guaca` (`auditoria`) | **git, fijado por `rev`** `23395f35` — **NO es el tag `v0.4.0`**, ver abajo | un tag es mutable: moverlo a un commit malicioso nos lo traería al construir (ataque Atomic Arch a AUR). El `Cargo.lock` ya lo fijaba; el `rev` lo hace explícito |

**El `rev` fijado NO es el tag `v0.4.0`, y confundirlos deshace el salto.** Lo
dijo una revisión el 2026-08-05, y aquí ponía lo contrario:

```
refs/tags/v0.4.0^{}  -> d786d1c3…   y ese commit pide quipu = "0.10"
rev fijado / main    -> 23395f35…   quipu = "0.11"
```

Son **9 commits** de distancia. Quien vea el desacuerdo y «alinee» el `rev` al
tag devuelve guaca a la 0.10 **en silencio** y mete dos entradas de quipu en el
lock — justo lo que el paso 2 existe para evitar. Si algún día se quiere que
coincidan, se mueve el TAG de guaca hacia delante; nunca el `rev` hacia atrás.

Y una lección de método que se queda escrita porque el error fue mío: aquí puso
un `ls-remote` contra el tag con la frase «comprobado así el 2026-08-05», y ese
comando **nunca se corrió** — se corrió el de `main`. Si se hubiera corrido,
habría salido en desacuerdo. Una comprobación que se escribe sin ejecutar es un
negativo que nadie produjo (directiva 30).

### Tunjo va SIEMPRE a la versión actual de Quipu — regla del 2026-08-05

Decisión de Juan, y sustituye a la que estuvo escrita aquí unas horas de
quedarse en la 0.10. Hoy: `quipu = "0.11"`, una sola entrada en el `Cargo.lock`.

**El motivo es que Quipu es NUESTRA.** La directiva 35 —agotar la línea actual,
el salto mayor con motivo y nunca por inercia— existe para no perseguir el
*major* de un tercero entre visitas al cliente. Aquí quien corta la release
decide también cuándo la toman los derivados. Y quedarse atrás cuesta lo que ir
al día no cuesta: si guaca y tunjo no van parejos, este binario acaba con **dos
copias de la pila cripto**.

**LA PUERTA, que es lo que separa la regla de la inercia: se sube, y si el
VECTOR FIJO se pone rojo, la subida SE DETIENE y vuelve a ser una decisión.** El
vector es `clave::una_clave_de_2026_sigue_abriendo`, y un rojo ahí dice que los
`.clave` en manos de peritos dejaron de abrirse. **No se regenera el literal.**

**EL ORDEN SON TRES PASOS, y el tercero es el que se olvida.** Medido el
2026-08-05: subir solo `quipu` deja el `Cargo.lock` con DOS entradas —la 0.11
nuestra y la 0.10 que arrastra guaca por el `rev`—, porque a guaca la tomamos
por commit fijado, no por versión.

1. guaca sube `quipu` y entra en su `main`.
2. Aquí se mueven **`quipu` Y el `rev` de guaca, en el MISMO commit**.
3. Control, antes de dar nada por bueno:
   `grep -c '^name = "quipu"$' Cargo.lock` tiene que dar **1**.

El `rev` se fija por COMMIT y nunca por tag —un tag es mutable—, y antes de
fijarlo se comprueba que el commit **está en `main`**. La forma que NO caduca es
la de alcanzabilidad, no la de igualdad: `main` recibe commits y una comparación
exacta se rompe sola aunque el `rev` siga siendo perfectamente válido.

```bash
git -C /mnt/data/guaca fetch -q origin
git -C /mnt/data/guaca merge-base --is-ancestor <rev> origin/main && echo alcanzable
```

Comprobado así el 2026-08-05 para `23395f35`.

**Y por eso tunjo NUNCA sube solo**, que es la razón del paso 2: guaca depende
de Quipu por su cuenta, así que subir aquí y no allí mete **dos copias de la
pila cripto** en el binario (19 duplicados → 20). Compila —a guaca solo le
cruzan bytes y `String`—, pero un ejecutable de peritaje con dos pilas dentro le
da dos respuestas a quien audite cuál firmó.

**Un cambio en Quipu o en guaca NO llega solo, y la regla no lo cambia — solo
dice qué hacer cuando llegue.** En `0.x` el minor hace de major para cargo, así
que `^0.11` no casará con la 0.12: publicar una versión nueva de Quipu **nunca**
actualiza a tunjo por `cargo update`. Hay que venir a editar el requisito, leer
qué cambió (`/mnt/data/decod/CLAUDE.md`) y pasar la puerta. Lo mismo con guaca
—cuyo `CLAUDE.md` propio está en `/mnt/data/guaca`—: hasta que no se mueva el
`rev`, aquí no entra nada.

## Comandos

```bash
# Los TRES del CI, exactos (.github/workflows/ci.yml). Verde local = estos tres.
# Van en DOS trabajos —`rust` y `cadena-suministro`—, así que cargo-deny puede
# ponerse rojo con las pruebas verdes: no es un extra, es un check obligatorio.
cargo clippy --all-targets --release -- -D warnings
cargo test --release
cargo deny check                             # cargo install cargo-deny --locked

cargo test --release --no-fail-fast          # para VER todos los fallos: sin esto
                                             # el primer binario rojo aborta el resto
cargo test --release --test integracion sellar_y_verificar_un_directorio  # una sola
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

Fuera de esa cadena quedan dos módulos pequeños que se usan desde todos:
`clave.rs` (la clave del perito, cifrada con contraseña sobre el contenedor de
Quipu) y `texto.rs` (`plano`, el saneador de pantalla del invariante 2).
`informe.rs` es el más grande —1.360 líneas— y se navega por sus submódulos:
`papel` (privado, el único que tiene el `String`), `dicho` (TODAS las constantes
de prosa) y los tipos `Dato`/`EnValla`/`Fijo`/`Segun<C>`/`PorFecha`.

## La superficie del CLI

`clave` · `sellar` · `verificar` · `acta` · `custodia {iniciar, evento, sello,
verificar}`. Los tres del invariante 3 son `verificar`, `acta` y
`custodia verificar`.

Para ejercer el binario **sin terminal** —lotes, pruebas, guiones— la contraseña
de la clave se puede dar en `TUNJO_CONTRASENA` (`main.rs`, `VAR_CONTRASENA`). Es
opt-in y tiene su coste declarado: queda en el entorno del proceso. Sin ella,
`rpassword` la pide por tty, y donde no hay terminal **falla** —no se queda
colgado— diciendo que la variable existe. El mensaje se puso el 2026-08-04: antes
salía el error del sistema en crudo, «No such device or address (os error 6)»,
que no nombraba ni la contraseña ni la variable que lo resuelve.

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
   cuya forma se validó). Para la pantalla, `texto::plano` (reexportado como
   `informe::plano`), por **dos** vías que hay que distinguir al añadir un campo:
   - **Saneado al nacer** lo que se construye a partir de texto ajeno: la
     `autoridad` de `Confianza` (`firma_cms.rs`) y el `motivo` de
     `EstadoSello::Invalido` (`custodia.rs`). Ahí ya no hace falta acordarse.
   - **Seguro por su forma** lo de `DatosSello`, que NO pasa por `plano`:
     `politica` es un OID (dígitos y puntos), `serie` es hex y `fecha_utc` sale de
     `DateTime`. Por eso `main.rs` los imprime en crudo. **Un campo de texto libre
     nuevo en `DatosSello` rompe el invariante en silencio** — o se sanea al
     construirlo, o no entra.
   - Lo que sigue siendo responsabilidad de cada `println!` son los campos crudos
     del acta (`caso.referencia`, `perito.nombre`, los `to_string()` de errores):
     en `main.rs` van todos envueltos en `informe::plano`.
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
10. **Nunca se escribe dentro del origen** (`recoleccion` no abre un solo archivo
    en escritura), y las tres órdenes que crean algo —`clave`, `sellar`,
    `custodia iniciar`— se niegan a sobrescribir su salida. La de `clave` es la
    más grave de las tres: pisarla deja sin verificar todas las actas firmadas
    con la anterior.

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

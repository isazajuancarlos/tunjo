<!--
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Tunjo

**Sellado criptográfico de evidencia digital y acta de cadena de custodia, con
firma post-cuántica.**

Un *tunjo* es la figura de tumbaga con la que los muiscas dejaban constancia
sellada de un acto. Esto hace lo mismo con bytes: acredita qué había, cuándo se
recogió y quién responde por ello, de forma que **un tercero pueda comprobarlo
sin creerle a nadie**.

## Qué problema resuelve

Un peritaje informático no suele perderse por no identificar al atacante. Se
pierde antes, cuando la contraparte pregunta cómo sabemos que esos archivos son
los que el perito recibió y no los que editó después.

La Ley 527 de 1999 (art. 11) dice qué debe valorar el juez ante un mensaje de
datos: la confiabilidad de cómo se generó, archivó o comunicó; **cómo se
conservó su integridad**; y cómo se identifica a su iniciador. Los tres extremos
son documentales. Tunjo los documenta.

## Cuándo NO hace falta

Vale la pena decirlo aquí y no en la letra pequeña: en Colombia los documentos
aportados a un proceso **se presumen auténticos**, y la Corte Suprema anuló en
STC3964-2023 un rechazo de demanda fundado en exigirle a un litigante la
«trazabilidad» de un poder enviado por correo — es una formalidad innecesaria de
las que el artículo 11 del CGP prohíbe.

Aportar prueba criptográfica donde la ley no la pide no refuerza nada: sugiere
que la presunción no bastaba. Esto sirve donde la presunción **no alcanza** —un
documento tachado o desconocido, una discusión sobre integridad y no sobre
autoría, una masa de datos que nadie aportó como propia, o la cadena de custodia
penal—. Ver `MARCO_JURIDICO.md` §6.1.

## Qué NO hace, y es deliberado

- **No concluye.** Ni intrusión, ni autoría, ni responsabilidad. Un detector
  automático mete en el dictamen una afirmación que el perito no puede defender
  línea por línea, y con ella se cae el resto.
- **No prueba el pasado.** Acredita desde el instante de la adquisición. Si el
  material ya venía alterado, el sello certifica fielmente material alterado.
- **No valida la firma de la autoridad de sellado** contra su cadena de
  certificados. Verifica que el sello corresponde a la firma del acta, guarda el
  token íntegro, y remite a `openssl ts -verify` para lo demás. Está medido: hay
  una prueba que fija ese límite y falla si algún día deja de ser cierto.
- **No escribe nunca dentro del origen.** Solo lee.

## Uso

```bash
# 1. Una vez: la clave del perito (queda cifrada con contraseña).
tunjo clave --ruta perito.clave

# 2. Sellar el material.
tunjo sellar /media/evidencia/caso-01 \
  --clave perito.clave \
  --referencia "RAD 05001-31-03-2026-00123" \
  --descripcion "Copia lógica del portátil entregado por el cliente" \
  --perito "Juan Carlos Isaza Arenas" \
  --identificacion "CC 1.234.567 — T.P. 000.000" \
  --metodo "copia lógica con bloqueador de escritura Tableau T8u" \
  --reloj "contrastado con reloj patrón de la SIC, desfase 0 s" \
  --sello http://timestamp.digicert.com \
  --salida acta.json

# 3. Verificar. Cualquiera, sin intervención del perito.
tunjo verificar acta.json                       # sello y coherencia interna
tunjo verificar acta.json --origen /media/...   # además, contra el disco

# 4. El acta legible que se anexa al dictamen.
tunjo acta acta.json --salida acta.md
```

Códigos de salida: `0` conforme, `1` la verificación falló, `2` error de
operación. Un guion de revisión necesita distinguirlos.

Para sellar por lotes —cincuenta elementos de un caso no se hacen a mano— la
contraseña puede darse en `TUNJO_CONTRASENA`. Es opt-in y tiene su coste: queda
en el entorno del proceso. Sin ella, el CLI la pide por terminal.

El acta legible lleva las **huellas** de la clave y de la firma, no sus valores
completos: la firma triple ocupa 46 KB en base64 y nadie coteja eso en papel. La
verificación se hace sobre el JSON; el Markdown es para leer.

## Cadena de custodia: la secuencia, no solo el instante

El acta prueba un **instante**: «esto existía en T0, con esta raíz Merkle,
firmado». Pero *cadena de custodia* significa la secuencia **ininterrumpida** de
quién tuvo la evidencia y qué hizo. Eso va en un artefacto aparte
(`cadena.json`), **encadenado por hash y firmado en triple**: cada evento apunta
al anterior, así que **borrar o reordenar rompe la cadena**, no solo alterarla.
El acta no se toca; la cadena se ancla a ella por el SHA-256 de sus bytes
canónicos, firmado en el evento génesis.

```bash
# Iniciar la cadena sobre un acta ya sellada (evento de adquisición).
tunjo custodia iniciar --acta acta.json --clave perito.clave \
  --actor "Juan Carlos Isaza Arenas" --identificacion "CC 1.234.567" \
  --descripcion "Copia lógica recogida en el domicilio del cliente"

# Añadir cada eslabón: transferencia, análisis, almacenamiento, presentación…
tunjo custodia evento --cadena cadena.json --clave perito.clave \
  --tipo transferencia --rol receptor \
  --actor "Laboratorio Forense X" --identificacion "NIT 900.000" \
  --descripcion "Entregada al laboratorio para extracción"

# Verificar la cadena entera: que arranque en el génesis y siga sin saltos
# (eslabones, firmas triple, secuencia). Con --acta comprueba además que
# corresponde a esa evidencia y que la firmó su mismo perito. La verifica
# cualquiera.
tunjo custodia verificar --cadena cadena.json --acta acta.json
```

Va firmada al **mismo nivel que el acta** (Ed25519 + ML-DSA-87 + SLH-DSA): la
custodia no puede ser el eslabón criptográficamente débil de la prueba.

**Lo que la cadena NO prueba.** Una cadena de hashes prueba que lo que hay es un
**prefijo íntegro**: que nadie borró, alteró ni reordenó nada *entre* el génesis
y el último eslabón presente. No puede probar que ese último eslabón sea el
último que existió — quien tenga la clave puede quedarse con los primeros N
eventos y entregar solo esos, y la cadena verifica ÍNTEGRA. Ninguna cadena de
hashes puede cerrar ese hueco por sí sola, y `tunjo` todavía no sella la cadena
como sella el acta: lo que lo cierra es **sacar el último hash del alcance de
quien custodia** —dejarlo en el expediente, comunicarlo a la contraparte— en
cada entrega. Que la cadena esté íntegra dice que no está *manipulada*, no que
esté *completa*.

## Fecha cierta: `--sello`

Sin sello de tiempo, un acta prueba **orden relativo**: la hora la pone el reloj
del perito, y un reloj adelantado produce un acta adelantada sin que nada lo
delate. Con `--sello URL`, una autoridad RFC 3161 certifica que la firma ya
existía en un instante dado.

En Colombia esto no es un servicio informal: el art. 161.5 del Decreto Ley 019
de 2012 lista el «estampado cronológico» entre las actividades de las entidades
de certificación digital, y **ONAC lo acredita citando RFC 3161 como su documento
normativo** (criterio CEA-3.0-07). El protocolo técnicamente correcto y el
jurídicamente reconocido son el mismo.

Se sella la **firma**, no el acta: así queda probado que la firma —y con ella
todo lo que cubre— ya existía. Si se pide sello y la autoridad no responde, el
sellado **falla**; no se cae en silencio a un acta sin fecha cierta.

## Cómo funciona el sello

1. Se recorre el origen **en solo lectura** y se calcula SHA-256 de cada archivo.
2. Con esos elementos se arma un **árbol de Merkle** con separación de dominio y
   el número de hojas atado a la raíz. Se usa árbol y no un hash único para poder
   probar que *un* archivo estaba en la adquisición sin exhibir los demás: en un
   peritaje, la contraparte tiene derecho a verificar el correo que la incrimina,
   no a leer los otros cuatro mil de la casilla.
3. El acta completa en JSON —incluidos método, reloj y lista de elementos— se
   firma con la **firma triple-híbrida de
   [Quipu](https://github.com/isazajuancarlos/quipu)**: Ed25519 +
   ML-DSA-87 (FIPS 204) + SLH-DSA-SHA2-256s (FIPS 205), las tres a la vez, y las
   tres deben validar.

La firma post-cuántica no es moda: una prueba judicial tiene que seguir
verificándose cuando el proceso llegue a casación, años después, y las firmas
clásicas de hoy no tienen garantizada esa vida útil.

## Ante la duda, ruido

- Un archivo que no se puede leer **detiene** el sellado. Si de verdad es
  ilegible, `--admitir-ilegibles` lo registra como `ERROR` y el acta lo declara
  expresamente: de él se acredita que existía y que la lectura falló, nada más.
- Si no se declara cómo se contrastó el reloj, el acta escribe **NO VERIFICADO**.
  No se supone que estaba bien.
- Un enlace simbólico se registra sin seguirlo.
- Verificar una firma válida sobre una raíz que no corresponde a los elementos
  **falla**: la raíz se recalcula siempre.

## Régimen de la firma

Es una **firma electrónica** del Decreto 2364 de 2012, no una «firma digital» de
las del artículo 28 de la Ley 527 (que exige entidad de certificación
acreditada). La distinción está en `MARCO_JURIDICO.md` §4 y se respeta en todo el
producto: llamarla de otro modo sería atribuirle un régimen que no tiene.

## Fundamento

`MARCO_JURIDICO.md` — Ley 527 de 1999, CGP arts. 226, 244 y 247, CPP art. 254,
Decreto 2364 de 2012, Ley 2213 de 2022, Ley 1273 de 2009 e ISO/IEC 27037, con las
fuentes consultadas y lo que queda pendiente de verificar.

## Verificación independiente

El verificador es libre y su código es público **por diseño**. Que un perito use
software propio es atacable —«usted valora con su producto»—, y la respuesta no
puede ser una promesa: un sello que solo su autor puede comprobar no es una
prueba, es una afirmación.

## Pruebas

```bash
cargo test --release   # en debug tarda decenas de minutos
```

**Siempre en release.** Argon2id y SLH-DSA sin optimizar tardan cerca de un
minuto por operación: la suite en modo debug no es lenta, es inviable.

Incluye una simulación de 240 contrastes (se altera un byte de cada uno de 120
archivos, se exige que señale ese y solo ese, y que al restaurarlo no queden
falsos positivos) y una prueba de sellado concurrente con temporizador.

## Licencia

AGPL-3.0-or-later. Titular: Juan Carlos Isaza Arenas. Ver `NOTICE`.

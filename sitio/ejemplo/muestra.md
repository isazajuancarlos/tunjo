# Acta de sellado de evidencia digital

**Referencia:** EJEMPLO\-DEMO\-001 \(no es un caso real\)

Material de muestra para demostrar la verificación — NO es evidencia real

## 1. Perito

- **Nombre:** Perito de demostración
- **Identificación:** C\.C\. 00\.000\.000 — demostración
- **Clave pública de verificación** — huella SHA-256:

```
086749a0 c83abcf3 17e00a7e 417c84e6 24aacf29 ff04f17e c8872625 adb8f5da (2688 bytes)
```

## 2. Método de adquisición

- **Origen:** \/tmp\/claude\-1000\/\-mnt\-data\/a52bb864\-5680\-412b\-8cc1\-9629201323ae\/scratchpad\/demo\-muestra\/evidencia
- **Método:** copia lógica en solo lectura \(demostración\)
- **Fundamento de la adquisición:** entrega voluntaria del titular \(demostración\)
- **Herramienta:** tunjo 0\.1\.0 \(sobre quipu\, firma triple\-híbrida\)
- **Algoritmos:** SHA\-256 \(contenido y Merkle\)\; firma 3\-de\-3\: Ed25519 \+ ML\-DSA\-87 \(FIPS 204\) \+ SLH\-DSA\-SHA2\-256s \(FIPS 205\)
- **Acceso declarado:** de solo lectura. Tunjo no escribe dentro del origen 
cuando es él quien adquiere; para un acta emitida por otra herramienta, esto 
es lo que declara el perito, no algo que este documento haya comprobado.

### Registro horario

- **Inicio (UTC):** 2026\-10\-12T16\:21\:58Z
- **Fin (UTC):** 2026\-10\-12T16\:21\:58Z
- **Desfase local respecto de UTC:** \-05\:00
- **Contraste del reloj:** NO VERIFICADO contra fuente externa de tiempo

## 3. Resumen

| Elementos | Leídos | Ilegibles | Bytes |
|---|---|---|---|
| 2 | 2 | 0 | 122 |

## 4. Raíz de integridad

Raíz del árbol de Merkle construido sobre los elementos listados en el
anexo. Cualquier cambio en un byte, en una ruta o en el orden produce una
raíz distinta.

```
8564175a977a533f6fc5102b03165731f86175f3bf286e63d3690161e1556b2b
```

## 5. Firma

- **Algoritmo:** SHA\-256 \(contenido y Merkle\)\; firma 3\-de\-3\: Ed25519 \+ ML\-DSA\-87 \(FIPS 204\) \+ SLH\-DSA\-SHA2\-256s \(FIPS 205\)
- **Cobertura:** la totalidad del acta en formato JSON, incluidos el
  listado de elementos y la raíz. **Comprobada.**

Huella SHA-256 de la firma:

```
da2ecbee 4a9e5d7b 8efcb7b8 8d5f7b14 d09ce2d4 6987b4d3 ecced2c3 7644036b (34483 bytes)
```

> La firma y la clave completas están en el archivo JSON, no en este
> documento: impresas ocuparían cientos de páginas que nadie cotejaría.
> **La verificación se hace sobre el JSON**; este documento es para leer,
> no para verificar.

## 6. Fecha cierta

**Esta acta NO lleva sello de tiempo de un tercero.**

En consecuencia acredita **orden relativo**, no fecha cierta oponible:
la hora que consta es la del reloj de la máquina del perito. Para fecha
oponible hace falta el sello de una autoridad de estampado cronológico.

## 7. Cómo verificar esta acta

Cualquier tercero puede comprobarla sin intervención del perito y sin
software propietario: el verificador es libre y su código es público.

```bash
tunjo verificar acta.json                 # firma y coherencia interna
tunjo verificar acta.json --origen RUTA   # además, contra el material en disco
```

## 8. Alcance y límites

Se deja constancia expresa de lo que esta acta **no** dice:

1. Acredita que los elementos listados tenían exactamente ese contenido en
   el momento de la adquisición. Para contrastar contra el material de hoy,
   `tunjo verificar --origen RUTA`, que es otra comprobación y la dice aparte.
2. **No** acredita qué contenía el material antes de la intervención del
   perito, ni quién lo creó, ni si fue alterado con anterioridad.
3. **No** contiene conclusión alguna sobre intrusiones, autoría o
   responsabilidad. Eso corresponde al dictamen, no a la herramienta.
4. La fecha registrada es la del reloj de la máquina, contrastada según se
   indica en el numeral 2. Sin sello de tiempo de tercero acreditado, prueba
   orden relativo, no fecha cierta oponible.

## 9. Fundamento normativo

- **Ley 527 de 1999, arts. 8 a 11.** Un mensaje de datos es íntegro si ha
  permanecido completo e inalterado; su fuerza probatoria se valora según
  la confiabilidad de la forma en que se generó, archivó o comunicó, la
  forma en que se conservó su integridad y la identificación de su
  iniciador. Los tres extremos son, exactamente, lo que esta acta documenta.
- **CGP (Ley 1564 de 2012), art. 247.** Los mensajes de datos se valoran en
  el formato en que fueron generados; de ahí que se sellen los archivos
  originales y no una impresión.
- **CGP, art. 226.** El dictamen debe ser claro, preciso, exhaustivo y
  detallado, y explicar los exámenes, métodos e investigaciones efectuados.
  Esta acta es el soporte metodológico de esa exigencia.
- **CPP (Ley 906 de 2004), art. 254.** Factores de la cadena de custodia:
  identidad, estado original, condiciones de recolección, preservación,
  embalaje y envío; lugares y fechas de permanencia y los cambios que cada
  custodio realizó.

Ver `MARCO_JURIDICO.md` para el detalle y las fuentes.

## Anexo. Elementos

| # | Ruta | Tipo | Bytes | SHA-256 | Modificado (UTC) | Estado |
|---|---|---|---|---|---|---|
| 1 | conversacion\.txt | archivo | 78 | f0027fc2df3867984c12a828ac0c1c48db9771e6025fe823205fb3534fc6f448 | 2026\-10\-12T16\:20\:55Z | leido |
| 2 | metadatos\.txt | archivo | 44 | a853198d8ad9d67eb156c963fe257580956f86c468725a3aace2bd85a5a53a0d | 2026\-10\-12T16\:20\:55Z | leido |

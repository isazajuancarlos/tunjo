<!--
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Marco jurídico del peritaje informático en Colombia

Investigación previa al diseño de Tunjo. Cada afirmación va con su fuente
consultada; lo que no pude contrastar contra el texto oficial queda marcado como
**pendiente de verificar** en vez de darse por bueno.

Fecha de consulta: **26 de julio de 2026**.

---

## 1. La pregunta que decide el diseño

Un dictamen informático no se pierde por no identificar al atacante. Se pierde
antes: cuando la contraparte pregunta *cómo sabemos que esos archivos son los
que el perito recibió y no los que editó después*. Todo lo que sigue gira
alrededor de eso.

La Ley 527 de 1999 dice, en su artículo 11, qué debe valorar el juez ante un
mensaje de datos:

> «la confiabilidad en la forma en la que se haya generado, archivado o
> comunicado el mensaje, la confiabilidad en la forma en que se haya conservado
> la integridad de la información, la forma en la que se identifique a su
> iniciador y cualquier otro factor pertinente».

Son tres extremos, y **los tres son documentales, no interpretativos**. Una
herramienta puede acreditarlos. Ninguna herramienta puede acreditar quién entró
al sistema. Por eso Tunjo hace lo primero y se abstiene de lo segundo.

El artículo 9 de la misma ley define la integridad de forma que se puede medir:
la información es íntegra si «ha permanecido completa e inalterada, salvo la
adición de algún endoso o de algún cambio que sea inherente al proceso de
comunicación, archivo o presentación». Un hash contesta exactamente esa
pregunta.

**Fuentes:** [Ley 527 de 1999 — Gestor Normativo, Función
Pública](https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=4276);
[texto en OEA](http://www.oas.org/juridico/spanish/cyb_col_Ley_527_de_1999.pdf);
[Sentencia C-662 de 2000](https://www.corteconstitucional.gov.co/relatoria/2000/c-662-00.htm).

---

## 2. Régimen probatorio civil

### 2.1 Valoración de mensajes de datos — CGP art. 247

Serán valorados como mensajes de datos los documentos aportados **en el mismo
formato en que fueron generados, enviados o recibidos**, o en uno que lo
reproduzca con fidelidad. Las impresiones en papel se valoran conforme a las
reglas de los documentos en papel.

**Consecuencia de diseño:** se sella el archivo original, no un PDF de él ni una
captura de pantalla. Un pantallazo de un WhatsApp es un documento en papel
electrónico: pierde metadatos y baja de categoría probatoria. Tunjo trabaja sobre
los archivos tal como están.

### 2.2 Autenticidad y su presunción — CGP art. 244

Un documento es auténtico cuando existe certeza sobre quién lo elaboró,
manuscribió, firmó, o sobre la persona a quien se atribuye. Los documentos
públicos y los privados —incluidos los mensajes de datos— **se presumen
auténticos mientras no sean tachados o desconocidos**.

**Consecuencia de diseño:** el sello no crea la autenticidad, que ya se presume.
Sirve para lo que ocurre *después* de la tacha: cuando la contraparte desconoce
el documento, el acta es lo que sostiene la carga.

### 2.3 El dictamen — CGP art. 226

Procede para verificar hechos que requieran conocimientos científicos, técnicos
o artísticos. No es admisible sobre puntos de derecho. Cada sujeto procesal
presenta un solo dictamen por materia, rendido por un perito, quien declara bajo
juramento —prestado con la firma— que su opinión es **independiente** y responde
a su real convicción profesional.

El dictamen debe ser **claro, preciso, exhaustivo y detallado**, explicar los
exámenes, métodos, experimentos e investigaciones efectuados, y acompañarse de
los documentos que lo fundamentan y de los que acreditan la idoneidad del perito.
Entre las exigencias enumeradas están: identidad del perito y de quienes
participaron, datos de localización, profesión y experiencia, publicaciones de
los últimos 10 años, casos en que ha sido designado en los últimos 4, causales de
impedimento, si el método empleado difiere del que usó en dictámenes anteriores o
del usual en su profesión, y la lista de documentos e información utilizados.

**Consecuencia de diseño:** el acta que produce Tunjo es el soporte metodológico
del dictamen — método, herramienta, algoritmos, fechas, lista de material—, no
el dictamen. Los datos del perito van en el acta porque el artículo los exige.

**Fuentes:** [CGP art. 226](https://leyes.co/codigo_general_del_proceso/226.htm),
[art. 244](https://leyes.co/codigo_general_del_proceso/244.htm),
[art. 247](https://leyes.co/codigo_general_del_proceso/247.htm).

---

## 3. Cadena de custodia — CPP art. 254

Texto literal del artículo 254 de la Ley 906 de 2004:

> «Con el fin de demostrar la autenticidad de los elementos materiales
> probatorios y evidencia física, la cadena de custodia se aplicará teniendo en
> cuenta los siguientes factores: identidad, estado original, condiciones de
> recolección, preservación, embalaje y envío; lugares y fechas de permanencia y
> los cambios que cada custodio haya realizado.»

Se registra el nombre e identificación de **todas** las personas que hayan tenido
contacto con los elementos. La cadena inicia donde se descubre o encuentra la
evidencia y termina por orden de autoridad competente.

**Consecuencia de diseño:** el acta traduce cada factor a un campo. `identidad` →
ruta y hash; `estado original` → raíz de Merkle; `condiciones de recolección` →
método declarado; `fechas` → registro horario en UTC con el desfase local. Lo que
un formato de papel resuelve con firmas sucesivas, aquí lo resuelve la firma
criptográfica sobre el conjunto.

**Pendiente de verificar:** el texto de los artículos 255 a 257 (responsabilidad,
aseguramiento e identificación) no pude recuperarlo del sitio consultado; hay que
contrastarlo con la edición oficial antes de citarlo. Igual con el **Manual de
Cadena de Custodia de la Fiscalía General de la Nación**, que es el que aplican
los peritos en materia penal y conviene mapear campo a campo.

**Fuente:** [CPP art. 254](https://leyes.co/codigo_de_procedimiento_penal/254.htm).

---

## 4. Firma: la distinción que hay que respetar

Aquí está la trampa en la que cae el marketing de casi todas las herramientas del
sector, y por eso se documenta explícitamente.

- **Firma digital** (Ley 527/1999 art. 2 lit. c, reglamentada por el Decreto 1747
  de 2000) es una especie con requisitos propios: exige, entre otras cosas,
  certificado emitido por una **entidad de certificación** acreditada. El
  artículo 28 le atribuye los efectos reforzados.
- **Firma electrónica** (Decreto 2364 de 2012, que reglamenta el art. 7 de la Ley
  527) es el género. Vale cuando el método sea **«tan confiable como apropiado
  para los fines con los cuales se generó o comunicó el mensaje»**, a la luz de
  todas las circunstancias. Rige la **neutralidad tecnológica**: ninguna
  disposición puede excluir un método que cumpla el artículo 7. Y **no** exige
  que la emita una entidad de certificación: puede implementarla el propio
  interesado o un proveedor de software.

**Consecuencia de diseño, y es una restricción, no una ventaja:** la firma de
Tunjo es una **firma electrónica** en el sentido del Decreto 2364 de 2012, y así
debe llamarse siempre. Decirle «firma digital» sería atribuirle un régimen que no
tiene. Lo que la hace *confiable y apropiada* es demostrable: clave bajo control
exclusivo del perito, cifrada con contraseña; algoritmos publicados; verificación
por cualquier tercero sin intervención del firmante; y código del verificador
abierto.

Si en un caso concreto se necesita el régimen del artículo 28, la salida es
firmar el acta con un certificado de una entidad de certificación acreditada —
que es compatible: se firma el mismo JSON.

**Fuentes:** [Decreto 2364 de 2012 — MinTIC](https://normograma.mintic.gov.co/mintic/compilacion/docs/decreto_2364_2012.htm);
[Decreto 2364 de 2012 — Función Pública](https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=50583).

---

## 5. Fecha cierta: el límite honesto

El acta registra la hora del reloj de la máquina. Eso prueba **orden relativo**,
no fecha oponible a terceros: un perito con el reloj adelantado produce un acta
con fecha adelantada, y el sello no lo delata.

Por eso el acta obliga a declarar cómo se contrastó el reloj, y si no se declara
**escribe que no se verificó** en lugar de callarlo. El paso siguiente —previsto,
no implementado— es el sello de tiempo de un tercero (RFC 3161) o el anclaje del
hash en un medio público, que sí da fecha cierta.

**Pendiente de verificar:** qué autoridades de sellado de tiempo están acreditadas
en Colombia y bajo qué régimen (ONAC / entidades de certificación digital).

---

## 6. Ley 2213 de 2022

Da vigencia permanente al Decreto 806 de 2020 sobre uso de las TIC en las
actuaciones judiciales. Interesa aquí porque consolida el mensaje de datos como
vehículo ordinario del proceso: los poderes especiales pueden conferirse por
mensaje de datos, sin firma manuscrita ni digital, con la sola antefirma, y **se
presumen auténticos** (art. 5); las notificaciones se practican por mensaje de
datos (art. 8). La Corte Suprema lo confirmó en STC3964 de 2023.

**Lectura para el producto:** el proceso ya corre sobre mensajes de datos. Lo que
escasea no es el reconocimiento legal del formato, sino la prueba de su
integridad cuando alguien la discute.

**Pendiente de verificar:** la numeración (arts. 5 y 8) y la referencia a
STC3964 de 2023 provienen de fuentes secundarias, no del texto oficial ni de la
providencia. Contrastarlas antes de citarlas en un escrito.

**Fuente:** [Ley 2213 de 2022 — Función Pública](https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=187626).

---

## 7. Ley 1273 de 2009 — los tipos penales

Confirmado contra la compilación del MinTIC. Sirve como **catálogo de lo que hay
que probar**, no como catálogo de lo que la herramienta detecta.

| Art. | Tipo | Verbo rector | Qué habría que acreditar |
|---|---|---|---|
| 269A | Acceso abusivo a un sistema informático | acceder sin autorización o fuera de lo acordado, o mantenerse contra la voluntad de quien puede excluirlo | registros de autenticación y sesión; el alcance de la autorización (contrato, política); permanencia tras la revocatoria |
| 269B | Obstaculización ilegítima de sistema o red | impedir u obstaculizar el funcionamiento o el acceso normal | disponibilidad antes/después; origen del tráfico o de la acción |
| 269C | Interceptación de datos informáticos | interceptar en origen, destino o dentro del sistema, sin orden judicial | punto de captura; ausencia de orden; configuración del dispositivo interceptor |
| 269D | Daño informático | destruir, dañar, borrar, deteriorar, alterar o suprimir datos o el sistema | estado anterior y posterior — aquí el sello previo es determinante |
| 269E | Uso de software malicioso | producir, traficar, adquirir, distribuir, vender, enviar, introducir o extraer del país | la muestra, su hash, su cadena de custodia y su comportamiento |
| 269F | Violación de datos personales | obtener, compilar, sustraer, ofrecer, vender, intercambiar, enviar, comprar, interceptar, divulgar, modificar o emplear | el conjunto de datos, su procedencia y el provecho |
| 269G | Suplantación de sitios web para capturar datos personales | diseñar, desarrollar, traficar, vender, ejecutar, programar o enviar páginas, enlaces o ventanas emergentes; modificar la resolución de nombres de dominio | copia sellada del sitio suplantador, DNS, certificados, tiempos |
| 269H | Circunstancias de agravación | — | redes estatales, servidor público, abuso de confianza, uso de tercero de buena fe, entre otras |
| 269I | Hurto por medios informáticos y semejantes | manipular un sistema o suplantar usuarios ante sistemas de autenticación | trazas de la transacción y del mecanismo de autenticación |
| 269J | Transferencia no consentida de activos | conseguir la transferencia con ánimo de lucro mediante manipulación informática | ruta del activo, ausencia de consentimiento |

**Por qué está esta tabla en un proyecto de software:** porque convierte la
adquisición en una decisión jurídica. Si la hipótesis es 269D, sellar el estado
actual es urgente y el estado anterior es la prueba; si es 269G, lo urgente es
capturar el sitio y su DNS antes de que caiga. **La lista dice qué recoger, y
nunca qué concluir.**

**Fuentes:** [Ley 1273 de 2009 — MinTIC](https://normograma.mintic.gov.co/mintic/compilacion/docs/ley_1273_2009.htm);
[Diario Oficial (PDF, SIC)](https://www.sic.gov.co/recursos_user/documentos/normatividad/Ley_1273_2009.pdf);
[Función Pública](https://www.funcionpublica.gov.co/eva/gestornormativo/norma.php?i=34492).

---

## 8. Estándar técnico: ISO/IEC 27037

Cubre **identificación, recolección, adquisición y preservación** de evidencia
digital — es decir, la fase inicial, que es justo donde opera Tunjo. Exige hashes
criptográficos del original y de la copia, y verificar que coincidan; SHA-256
como mínimo. Principios: relevancia, confiabilidad y suficiencia.

Citarla en el dictamen tiene un efecto concreto: el método deja de ser «lo que
hizo el perito» y pasa a ser un estándar internacional al que el perito se
sujeta, que es lo que el art. 226 del CGP pregunta cuando indaga si el método
difiere del usual en la profesión.

**Pendiente de verificar:** el texto de 27037 es de pago; lo consultado son
resúmenes técnicos. Antes de afirmar conformidad hay que leer la norma. **No
declarar «cumple ISO 27037» hasta entonces** — es exactamente el tipo de
afirmación que se cae en contrainterrogatorio. Relacionadas: 27041 (idoneidad del
método), 27042 (análisis e interpretación), 27043 (principios de investigación).

**Fuentes:** [ISO/IEC 27037 — resumen](https://ciberseguridad.com/normativa/espana/iso-iec-27037-evidencia-digital/);
[guía de cadena de custodia digital](https://guiacadenadecustodiadigital.wordpress.com/iso-27037/).

---

## 9. Lo que este proyecto NO hace, y por qué

1. **No concluye.** Ni intrusión, ni autoría, ni responsabilidad. Un detector
   automático de ataques mete en el dictamen una afirmación que el perito no
   puede defender línea por línea, y con ella cae todo lo demás.
2. **No prueba el pasado.** Acredita desde el instante de la adquisición. Si el
   material ya venía alterado, el sello certifica fielmente material alterado.
3. **No sustituye al perito.** El artículo 226 exige idoneidad, imparcialidad y
   método; el software es parte del método.
4. **No da fecha cierta** sin sello de tiempo de tercero (§5).

---

## 10. Nota sobre imparcialidad

El artículo 226 del CGP exige que el perito jure independencia. Que el perito use
software propio es atacable —«usted valora con su producto»—, y la respuesta no
puede ser una promesa. Por eso el verificador es **libre y público**: cualquier
tercero comprueba el acta con el código a la vista y sin pedirle nada al autor.
Un sello que solo su autor puede verificar no es una prueba, es una afirmación.

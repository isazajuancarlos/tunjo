<!--
SPDX-FileCopyrightText: 2026 Juan Carlos Isaza Arenas
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Marco jurídico del peritaje informático en Colombia

Investigación previa al diseño de Tunjo. Cada afirmación va con su fuente
consultada; lo que no pude contrastar contra el texto oficial queda marcado como
**pendiente de verificar** en vez de darse por bueno.

Fecha de consulta: **26 de julio de 2026**. Las fuentes que quedaron abiertas en
la primera vuelta se verificaron el mismo día; lo que sigue sin comprobar está
marcado y es solo lo que no pude leer en su texto original.

---

## 1. La pregunta que decide el diseño

Un dictamen informático no se pierde por no identificar al atacante. Se pierde
antes: cuando la contraparte pregunta *cómo sabemos que esos archivos son los
que el perito recibió y no los que editó después*. Todo lo que sigue gira
alrededor de eso.

> **Pero esa pregunta no siempre es legítima, y conviene saberlo antes de
> ofrecer una respuesta.** La ley presume la autenticidad de los documentos que
> se aportan a un proceso, y la Corte Suprema anuló en **STC3964-2023** un
> rechazo de demanda fundado precisamente en exigirle a un litigante la
> «trazabilidad» de un poder enviado por correo: es una formalidad innecesaria de
> las que el artículo 11 del CGP prohíbe. Aportar prueba criptográfica donde la
> ley no la pide no refuerza un dictamen —sugiere que la presunción no bastaba— y
> empuja al juez a exigir lo que tiene vedado exigir.
>
> El sello sirve donde la presunción **no alcanza**: documento tachado o
> desconocido, discusión sobre **integridad** y no sobre autoría, masa de datos
> que nadie aportó como propia, y materia penal. El detalle, en §6.1.

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

### 3.1 A quién obliga — art. 255

La responsabilidad no es solo de los servidores públicos:

> «Los particulares que por razón de su trabajo o por el cumplimiento de las
> funciones propias de su cargo […] entren en contacto con elementos materiales
> probatorios y evidencia física, son responsables por su recolección,
> preservación y entrega a la autoridad correspondiente.»

**Consecuencia para un perito de parte:** la cadena de custodia lo obliga
directamente, no por analogía. No es una buena práctica que adopta por
prudencia: es el estándar con el que se mide su trabajo.

### 3.2 La sustitución del objeto por su representación — art. 256

Para «macroelementos» —naves, aeronaves, vehículos, máquinas, grúas y similares—
el objeto se documenta por videograbación o fotografía, **y esas imágenes
reemplazan al objeto físico en el juicio oral**.

**Por qué importa aquí, y no es una analogía forzada:** el ordenamiento ya acepta
que un elemento probatorio se sustituya por su representación fiel cuando
conservar el original es impracticable. Un servidor en producción es exactamente
ese caso — no se incauta, se copia. Lo que el artículo exige a cambio es que la
representación sea fiel y esté documentada, que es justo lo que un sello acredita.

### 3.3 Quién custodia — art. 257

> «El servidor público que, en actuación de indagación o investigación policial,
> hubiere embalado y rotulado el elemento material probatorio y evidencia física,
> lo custodiará.»

Quien embala responde. En digital, «embalar y rotular» es precisamente calcular
la huella y levantar el acta.

### 3.4 El manual vigente NO es el de la Fiscalía de 2016

Conviene decirlo así de directo porque es un error fácil, y esta sección lo
contenía: la Resolución 0-2369 de 2016 **está derogada**.

El instrumento vigente es el **Manual del Sistema de Cadena de Custodia**,
adoptado por el **Acuerdo 001 del 18 de abril de 2018 del Consejo Nacional de
Policía Judicial** —órgano que integran, y que firman, el Fiscal General, el
Procurador General, el Contralor General, el Director de la Policía Nacional y el
Director del Instituto Nacional de Medicina Legal—. Su artículo 15 dispone que
rige **dos meses después** de expedido y que desde esa fecha «se entenderán
derogados el Manual Único de Policía Judicial aprobado mediante acta No. 053 del
13 de mayo de 2005 [y] el Manual de Procedimientos para Cadena de Custodia
adoptado mediante Resolución No. 0-2369 de 2016».

No es un cambio de rótulo: cambia el emisor —de la Fiscalía sola a los cinco
organismos con funciones de policía judicial— y su artículo 3 lo declara de
aplicación nacional y «carácter vinculante y obligatorio». El artículo 6 confirma
que las reglas obligan a «cada servidor público **y particular** que tenga
relación con EMP y EF».

Tres novedades del Acuerdo importan aquí:

- **Denominación** (art. 6.a): el manual «modifica el término *procedimientos*
  por *sistema*». Citar «Manual de Procedimientos» delata que se está citando la
  versión vieja.
- **Capacidad demostrativa** (art. 6.b): es el enfoque que guía esta versión, y
  conforme a él «el objetivo último de la cadena de custodia va **más allá de la
  autenticidad** de los EMP y EF». Es exactamente la distinción que sostiene este
  proyecto: acreditar que algo es auténtico y acreditar que puede *demostrar* algo
  no son la misma operación.
- **ID o código del EMP** (art. 6.e): los formatos incorporan una casilla de
  identificador. En digital, ese identificador estable puede ser la huella
  criptográfica del contenido, que además no depende de quién rotule.

El manual adoptado consta de **once apartados** (art. 7), entre ellos «Aspectos
transversales al Sistema de Cadena de Custodia», «Procedimientos del Sistema» y
«Formatos».

**Pendiente de verificar, y es lo que falta para cerrar del todo:** tengo el
**acto que adopta** el manual, no el texto de sus once apartados. Sin él no puedo
afirmar si la versión de 2018 trata la evidencia digital ni si incorpora el hash
—hay fuentes secundarias que lo sostienen y no las he podido comprobar—. La
observación de que el sistema está construido sobre el objeto físico se apoya en
la edición anterior, cuyo índice sí leí; para la vigente, es una hipótesis.

**Nota de procedencia, por coherencia con lo que este proyecto predica:** la copia
del Acuerdo se descargó de `medicinalegal.gov.co`, cuya cadena TLS no validó en
la consulta; hubo que desactivar la verificación del certificado. El documento es
internamente consistente y aparece firmado, pero **una copia obtenida por un canal
que no se pudo autenticar no es una fuente primaria en sentido estricto**. Antes
de citarlo en un dictamen, contrastarlo contra otra copia oficial.
SHA-256 de la copia consultada:
`de7471770a3d4c27de1e15ea90d00ac402f6933a1854bd720151ab3b089eb632`.

**Hallazgo, y es el que da sentido a este proyecto:** la resolución **no contiene
disposiciones específicas sobre evidencia digital**. El sistema de cadena de
custodia colombiano está construido sobre el objeto físico —embalaje, rótulo,
traslado—, y para un disco o un buzón esas categorías hay que traducirlas. La
traducción no está en la norma; la pone el perito, y por eso tiene que poder
justificarla.

### 3.5 Qué contenía la edición anterior, y por qué se deja escrito

Leído el índice del *Manual de Procedimientos para Cadena de Custodia* —la
edición **derogada**, la única cuyo texto pude consultar—, sus **trece
procedimientos** (FGN-CC-\*) van del manejo del lugar de los hechos al envío al
almacén de evidencias, la recepción en el laboratorio y la disposición final. Y
cuando distingue categorías, las distingue **por el origen** del elemento
—asistencia judicial con el extranjero, agente encubierto, entrega vigilada,
entidades prestadoras de servicios de salud—, **nunca por su naturaleza**. No
había procedimiento de evidencia digital, y no parece un descuido: el sistema
está construido sobre el objeto que se embala, se traslada y se almacena.

Se deja constancia porque es el antecedente que explica el enfoque —y porque
sirve de hipótesis a verificar contra la edición de 2018—, no como descripción
del derecho vigente.

**Fuentes:** [CPP art. 254](https://leyes.co/codigo_de_procedimiento_penal/254.htm),
[art. 255](https://leyes.co/codigo_de_procedimiento_penal/255.htm),
[art. 256](https://leyes.co/codigo_de_procedimiento_penal/256.htm),
[art. 257](https://leyes.co/codigo_de_procedimiento_penal/257.htm);
[Acuerdo 001 de 2018 del Consejo Nacional de Policía Judicial (PDF, INMLCF)](https://www.medicinalegal.gov.co/documents/20143/1207211/2018_001_Manual_cadena_custodia.pdf);
[Resolución FGN 2369 de 2016, **derogada** (normograma JEP)](https://jurinfo.jep.gov.co/normograma/compilacion/docs/resolucion_fiscalia_2369_2016.htm);
[Manual de Procedimientos para Cadena de Custodia, edición anterior (PDF, Rama Judicial)](https://sidn.ramajudicial.gov.co/SIDN/DOCTRINA/TABLAS%20DE%20CONTENIDO%20Y%20TEXTOS%20COMPLETOS/345%20-%20DERECHO%20PROCESAL%20PENAL%20Y%20PROCESAL%20CIVIL/14843_Manual_de_procedimientos_para_Colombia.pdf).

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

### 5.1 En Colombia eso tiene régimen propio, y encaja

**Verificado en fuente primaria**, y el resultado es mejor de lo esperado: el
sellado de tiempo no es aquí un servicio informal, sino una **actividad
acreditada**.

- El **artículo 161, numeral 5, del Decreto Ley 019 de 2012** enumera entre las
  actividades de las entidades de certificación digital: «ofrecer o facilitar los
  servicios de registro y **estampado cronológico** en la generación, transmisión
  y recepción de mensajes de datos».
- **ONAC** acredita esa actividad bajo el criterio **CEA-3.0-07**, y el anexo del
  certificado lista como documento normativo del servicio, literalmente, **RFC
  3161 (agosto 2001)** —junto con RFC 3628, RFC 5905, SHA-256 y FIPS 140-2 nivel
  3—.
- Ejemplo concreto y comprobado: **OLIMPIA IT S.A.S**, acreditación
  **21-ECD-001**, con «Estampado cronológico» en el alcance aprobado y vigencia
  hasta el 30 de junio de 2029.
- Marco de requisitos de la entidad: Ley 527 de 1999, Decreto Ley 019 de 2012 y
  **Decreto 333 de 2014**.

**Consecuencia de diseño:** el sello de tiempo que Tunjo tiene previsto **es
exactamente el protocolo que ONAC usa para acreditar el servicio en Colombia**.
No hay que elegir entre lo técnicamente correcto y lo jurídicamente reconocido:
es el mismo RFC. Al implementarlo, la fecha deja de depender del reloj del perito
y pasa a apoyarse en un tercero acreditado — que es lo que convierte el orden
relativo en fecha oponible.

**Fuentes:** [ONAC — esquema ECD](https://onac.org.co/informacion-por-esquemas-de-acreditacion/certificacion-digital-ecd/);
[certificado 21-ECD-001 y su anexo de alcance (PDF)](https://onac.org.co/certificados/21-ECD-001.pdf);
[directorio de acreditados](https://onac.org.co/directorio-de-acreditados/).

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

**Verificado** contra el texto de la ley: el **artículo 5** es el de los poderes
—«se podrán conferir mediante mensaje de datos, sin firma manuscrita o digital,
con la sola antefirma»— y el **artículo 8** el de las notificaciones personales
por mensaje de datos, que se entienden surtidas transcurridos dos días hábiles
desde el envío.

### 6.1 STC3964-2023: leída, y corrige el encuadre de este proyecto

Corte Suprema de Justicia, **Sala de Casación Civil y Agraria**, **STC3964-2023**,
radicación **50001-22-13-000-2023-00022-01**, M.P. **Aroldo Wilson Quiroz
Monsalvo**, **26 de abril de 2023**. Verificada en su texto.

**Los hechos son exactamente nuestro problema.** Un litigante aportó un poder en
PDF conferido por correo. El juzgado lo inadmitió y luego rechazó la demanda
porque no se acreditó la «**trazabilidad**» de haberlo obtenido por mensaje de
datos. El actor aportó un archivo `.EML` para probar el envío, y después un
pantallazo del correo. No bastaron.

**Y la Corte le dio la razón al litigante, no al juzgado.** El poder por mensaje
de datos se presume auténtico (art. 5 de la Ley 2213), de modo que exigir prueba
de trazabilidad es una **formalidad innecesaria** de las que el artículo 11 del
CGP prohíbe: requerir «cadenas de correos electrónicos que permitan establecer
una autoría o trazabilidad **que se presume por mandato legal**». El juzgado
incurrió en defecto adjetivo y se dejó sin efecto su auto.

> **Corrección al encuadre de §1, y es importante.** La presunción de
> autenticidad es fuerte y opera sola. Vender el sello como si toda prueba
> digital necesitara respaldo criptográfico sería **jurídicamente equivocado** —y
> además invitaría al juez a exigir lo que esta sentencia le prohíbe exigir—.
>
> Donde el sello sirve es donde la presunción **no alcanza**:
>
>   1. Cuando el documento es **tachado de falso o desconocido** (art. 244 CGP):
>      ahí la presunción cae y hay que probar.
>   2. Cuando la discusión no es de **autoría** sino de **integridad**: qué decía
>      el archivo entonces, y si cambió después. La presunción resuelve quién lo
>      hizo, no si fue alterado.
>   3. Cuando no hay un documento aportado por una parte sino una **masa de
>      datos** —un disco, un buzón, un servidor— que nadie ha presentado como
>      suyo y sobre la que no pesa presunción alguna.
>   4. En **materia penal**, donde no rige esta presunción sino la cadena de
>      custodia de los artículos 254 a 257.
>
> Fuera de esos casos, lo correcto es invocar la presunción y no ofrecer prueba
> adicional. Un perito que aporta lo que la ley no exige no refuerza su dictamen:
> sugiere que la presunción no le bastaba.

**Y un segundo hallazgo, que amplía el alcance en vez de estrecharlo.** La Corte
reitera que «mensaje de datos» es mucho más amplio que «mensaje de correo
electrónico»: comprende, por el literal a) del art. 2 de la Ley 527, la
información *generada, enviada, recibida, **almacenada** o comunicada*. En sus
palabras, «no es solamente el que se envía a un destinatario o que circula por
medio de las TIC sino **cualquier dato, declaración o información que repose en
un continente tecnológico**», sea que circule o no.

**Consecuencia:** un archivo en reposo en un disco es, para el derecho
colombiano, un mensaje de datos — con todo el régimen de la Ley 527 aplicable,
incluida la regla de integridad del art. 9 y los criterios de valoración del art.
11. El alcance deliberado de esta herramienta (datos en reposo) no es un recorte
técnico: coincide con el concepto legal.

**Fuente:** [STC3964-2023, texto de la providencia (PDF, Universidad Externado)](https://procesal.uexternado.edu.co/wp-content/uploads/sites/9/2023/06/sentencia-de-corte-suprema-de-justicia-sala-de-casacin-civi_es.pdf).

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

**Estado de la norma, verificado:** la edición vigente sigue siendo la primera,
**ISO/IEC 27037:2012**, *confirmada sin cambios en 2018*. No está retirada ni
sustituida, así que citarla no arrastra el defecto de invocar una norma derogada.

**Lo que sigue pendiente, y la regla no cambia:** el texto es de pago y no lo he
leído; lo consultado son resúmenes técnicos y el resumen de alcance del catálogo.
**No declarar «cumple ISO 27037» hasta leerla** — es exactamente el tipo de
afirmación que se cae en contrainterrogatorio, y la diferencia entre «sigue los
principios de» y «cumple» es justo la que la contraparte va a explotar.
Relacionadas: 27041 (idoneidad del método), 27042 (análisis e interpretación),
27043 (principios de investigación).

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

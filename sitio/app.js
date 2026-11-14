// SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Verificador de la página: carga el wasm y pinta el veredicto. Externo (no inline)
// para servirse bajo CSP `script-src 'self' 'wasm-unsafe-eval'` sin `'unsafe-inline'`.
// Todo el DOM se construye con textContent / createTextNode: los campos del acta son
// texto ajeno (ya neutralizado por `plano` en el wasm) y NUNCA se interpolan como HTML.
import init, { verificar_acta, sha256_hex } from './verificador/verificador_wasm.js';

const $estado = document.getElementById('verif-estado');
const $res = document.getElementById('verif-resultado');
const $acta = document.getElementById('f-acta');
const $arch = document.getElementById('f-arch');

let listo = false;
let ultimo = null;               // último veredicto del wasm
const shaPorNombre = new Map();  // basename del archivo aportado -> su sha256

const base = (ruta) => ruta.split(/[\\/]/).pop();
const leer = (file) => new Promise((ok, no) => {
  const r = new FileReader();
  r.onload = () => ok(new Uint8Array(r.result));
  r.onerror = () => no(r.error);
  r.readAsArrayBuffer(file);
});

init()
  .then(() => { listo = true; $estado.textContent = 'Verificador listo. Elija un acta.'; })
  .catch((e) => { $estado.textContent = 'No se pudo cargar el verificador: ' + e; });

function filaMeta(etiqueta, valor, nota) {
  if (valor === undefined || valor === '') return;
  const p = document.createElement('p'); p.className = 'meta-acta';
  const b = document.createElement('b'); b.textContent = etiqueta + ': ';
  p.append(b, document.createTextNode(valor));
  if (nota) {
    const s = document.createElement('span'); s.className = 'limite';
    s.textContent = '  ' + nota; p.append(s);
  }
  $res.append(p);
}

function render() {
  if (!ultimo) return;
  const v = ultimo;
  $res.hidden = false;
  $res.replaceChildren();

  // Veredicto de integridad+firma. Acredita respecto de la clave que trae el acta;
  // NO afirma identidad del perito (eso lo cierra comparar la huella de abajo).
  // Tres estados, no dos: «no_verificable» (el verificador no conoce la versión del
  // acta) NO es un veredicto de forja —pintarlo de ✗ rojo repetiría en la web el fallo
  // que la negociación de versión corrige—. Se pinta en aviso (⚠), ni conforme ni
  // rechazada. Si el wasm es viejo y no manda `estado`, cae al comportamiento de dos
  // estados (compat).
  const noVerificable = v.estado === 'no_verificable';
  const vd = document.createElement('div');
  vd.className = 'verdicto ' + (noVerificable ? 'v-aviso' : (v.ok ? 'v-ok' : 'v-mal'));
  vd.textContent = (noVerificable ? '⚠ ' : (v.ok ? '✓ ' : '✗ ')) + v.mensaje;
  $res.append(vd);

  filaMeta('Referencia', v.referencia);
  filaMeta('Perito', v.perito);
  // H3 (concilio 2026-10-12): la huella de la clave. Sin esto, un acta forjada con una
  // clave cualquiera verifica ✓ y se presenta como del perito. Comparar la huella con la
  // que el perito publicó por otro canal es lo que ata la firma a ESE perito.
  filaMeta('Huella de la clave del perito', v.huella_clave,
    '← compárela con la que el perito publicó. Si no coincide, la firma es de OTRA clave.');
  filaMeta('Raíz de integridad', v.raiz);

  // H1 (concilio): el estado REAL del sello de tiempo, ya verificado por el wasm.
  if (v.sello) {
    const clase = { ausente: 'cot-na', sin_anclar: 'cot-ok', invalido: 'cot-mal' }[v.sello.estado] || 'cot-na';
    const p = document.createElement('p'); p.className = 'meta-acta';
    const b = document.createElement('b'); b.textContent = 'Sello de tiempo: ';
    const s = document.createElement('span'); s.className = clase;
    const tira = { ausente: 'ausente', sin_anclar: 'válido, SIN ANCLAR', invalido: 'NO verifica' };
    s.textContent = tira[v.sello.estado] || v.sello.estado;
    p.append(b, s);
    if (v.sello.fecha) p.append(document.createTextNode('  (' + v.sello.fecha + ')'));
    $res.append(p);
    const n = document.createElement('p'); n.className = 'meta-acta limite';
    n.textContent = v.sello.mensaje; $res.append(n);
  }

  const els = v.elementos || [];
  if (!els.length) return;

  // Cotejo por basename: si dos elementos comparten nombre de archivo, el cotejo por
  // nombre es ambiguo y NO se puede decidir sin la ruta completa — se avisa en vez de
  // dar un ✓/✗ que podría mentir (D20).
  const cuenta = new Map();
  for (const el of els) { const n = base(el.ruta); cuenta.set(n, (cuenta.get(n) || 0) + 1); }

  const h = document.createElement('p'); h.className = 'meta-acta';
  h.append(document.createTextNode('Elementos (' + els.length + ') — cotejo del contenido:'));
  $res.append(h);

  for (const el of els) {
    const d = document.createElement('div'); d.className = 'elem';
    const r = document.createElement('span'); r.className = 'ruta'; r.textContent = el.ruta;
    const c = document.createElement('span');
    const nombre = base(el.ruta);
    if (el.cotejable === false) {
      c.className = 'cot-na';
      c.textContent = '— sin huella (' + (el.estado || 'no cotejable') + ')';
    } else if (cuenta.get(nombre) > 1) {
      c.className = 'cot-na';
      c.textContent = '— nombre repetido, coteje con el binario';
    } else {
      const aportado = shaPorNombre.get(nombre);
      // Paso 5: comparar en minúsculas. `sha256_hex` ya las da; normalizar el del acta
      // evita un falso «NO coincide» si viniera en mayúsculas (no puede crear un falso ✓:
      // el hex es el mismo valor en cualquier caja).
      const declarado = (el.sha256 || '').toLowerCase();
      if (aportado === undefined) { c.className = 'cot-na'; c.textContent = '— no aportado'; }
      else if (aportado === declarado) { c.className = 'cot-ok'; c.textContent = '✓ coincide'; }
      else { c.className = 'cot-mal'; c.textContent = '✗ NO coincide'; }
    }
    d.append(r, c); $res.append(d);
  }
}

$acta.addEventListener('change', async () => {
  if (!listo || !$acta.files.length) return;
  // Paso 5 del concilio: borrar el veredicto anterior ANTES de procesar el nuevo. Si el
  // WASM lanzara, sin esto el panel seguiría mostrando el ✓ verde de la otra acta — un
  // juez vería un veredicto que no corresponde al archivo que cargó (D20).
  ultimo = null; $res.hidden = true; $res.replaceChildren();
  // Acta nueva: el cotejo de la anterior no vale (basenames que podrían chocar). Se
  // vacía y se vuelve a leer de los archivos aún seleccionados, si los hay.
  shaPorNombre.clear();
  try {
    ultimo = JSON.parse(verificar_acta(await leer($acta.files[0])));
    for (const f of $arch.files) shaPorNombre.set(f.name, sha256_hex(await leer(f)));
    render();
  } catch (e) { $estado.textContent = 'Error leyendo el acta: ' + e; }
});

$arch.addEventListener('change', async () => {
  if (!listo) return;
  // Reconstruir desde la selección ACTUAL (un FileList nuevo reemplaza, no acumula):
  // sin esto, deseleccionar un archivo dejaba su sha fantasma en el mapa.
  shaPorNombre.clear();
  try {
    for (const f of $arch.files) shaPorNombre.set(f.name, sha256_hex(await leer(f)));
    render();
  } catch (e) { $estado.textContent = 'Error leyendo los archivos: ' + e; }
});

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Juan Carlos Isaza
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Publica el KIT de tunjo (página + verificador WASM) en
# verificar.abogadoisaza.com.
#
# Casa: subdominio de la práctica jurídica (la audiencia es judicial —juez,
# perito, contraparte— y la credencial de perito vive en abogadoisaza.com), con
# co-marca Xiliux por la DECISIÓN 0009 (la herramienta GRATIS puede vincular las
# dos identidades; lo COMERCIAL sigue bajo la regla de no-cruce). Vhost y raíz
# APARTE de abogadoisaza.com: la página jurídica es estática pura con CSP
# `default-src 'none'`, y el verificador ejecuta WASM —no pueden compartir CSP—.
#
# POR QUÉ EN BASH Y NO EN RUST (directiva 38): el cuerpo entero son líneas de
# órdenes de OTROS programas —ssh, tar, certbot, nginx, curl— y tiene que poder
# lanzarse con `!` sin un paso de compilación entre editarlo y usarlo; un binario
# metería el modo de fallo del que avisa la directiva, el ejecutable viejo junto
# a la fuente nueva.
#
# LA SECUENCIA ENTERA VA AQUÍ: construir, comprobar, respaldar, comparar, subir,
# certificar, activar y verificar CONTRA EL DOMINIO —que es la verdad de lo
# desplegado, no el `is-active`—.
#
# ---------------------------------------------------------------------------
# LO QUE SE HEREDA DE desplegar.sh de juancarlosisaza (medido en ESTE servidor)
# ---------------------------------------------------------------------------
#
# 1. EL VHOST POR DEFECTO CIERRA SIN RESPONDER (`return 444`). Un nombre sin
#    bloque propio no recibe NADA — ni el reto de Let's Encrypt. Por eso va EN
#    DOS FASES: primero un vhost solo-HTTP que atiende el reto (sin
#    `ssl_certificate`, así `nginx -t` pasa), y con el certificado emitido se
#    sustituye por el definitivo.
#
# 2. IPv6 SIN SERVIDOR POR DEFECTO. `000-default` es IPv4 puro; en IPv6 el primer
#    bloque del glob que escuche en `[::]` absorbe los nombres sin vhost. Este
#    archivo NO pone `listen [::]` (y el paso 0 EXIGE que el nombre no tenga
#    AAAA): con AAAA, una visita por IPv6 caería en el vhost de otro sitio —error
#    de certificado y la práctica jurídica resolviendo contra infraestructura de
#    otra marca, justo lo que la regla de identidad prohíbe—. La compuerta
#    convierte ese agujero en un rojo en vez de en un silencio.
#
# 3. DNS DE LA RED INTERCEPTADO: el puerto 53 de esta red miente; se pregunta al
#    MUNDO por DoH (443) y la verificación final usa `curl --resolve` para medir
#    el SERVIDOR y no el DNS.
# ---------------------------------------------------------------------------
set -euo pipefail

SERVIDOR="debian@192.99.42.108"
DOMINIO="verificar.abogadoisaza.com"       # subdominio de servicio: SIN www/.net
RAIZ="/var/www/verificar.abogadoisaza"
ESPERADO="192.99.42.108"
VHOST="verificar.abogadoisaza"             # nombre del archivo en sites-*
SITIO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # tunjo/sitio/
REPO="$(cd "$SITIO/.." && pwd)"            # tunjo/
SELLO="$(date +%Y%m%d-%H%M%S)"
# Lista BLANCA de lo que se publica, a nivel superior (archivos y directorios).
# Con una lista negra, cualquier cosa que apareciera mañana en sitio/ saldría
# sola. `desplegar.sh`, `.gitignore` y un `tunjo`/`*.clave` que caiga aquí NO
# están en la lista y por tanto no se publican.
PUBLICOS=(index.html app.js xiliux-logo.webp verificador ejemplo)
# Artefactos que produce el build (git-ignored a propósito) y SÍ se publican.
# Allowlist EXPLÍCITO: los .d.ts que wasm-bindgen también genera NO se sirven.
GENERADOS=(verificador/verificador_wasm.js verificador/verificador_wasm_bg.wasm)

decir() { printf '\n== %s\n' "$*"; }

# TRES MODOS. La fase 1 es cara (tira el sitio mientras pasa el certificado), así
# que solo se paga para emitir.
#   (sin bandera)      completo: primera publicación. Fases 1 y 2 + certificado.
#   --solo-contenido   construye, sube y verifica. No toca nginx. Modo normal.
#   --solo-vhost       reescribe el vhost definitivo y recarga, sin corte.
MODO=completo
case "${1:-}" in
  --solo-contenido) MODO=contenido ;;
  --solo-vhost)     MODO=vhost ;;
  "") ;;
  *) echo "Uso: $0 [--solo-contenido | --solo-vhost]"; exit 2 ;;
esac

# UN SOLO manejador de EXIT (en bash un segundo `trap ... EXIT` REEMPLAZA al
# primero). Imprime la vuelta atrás al ABORTAR, no solo al terminar bien.
MONTAJE=""
al_salir() {
  local codigo=$?
  [ -n "$MONTAJE" ] && rm -rf "$MONTAJE"
  [ $codigo -eq 0 ] && return 0
  echo
  echo "== ABORTADO (código $codigo)."
  echo "Si ya se había activado el vhost, la vuelta atrás es:"
  echo "  ssh $SERVIDOR 'sudo rm -f /etc/nginx/sites-enabled/$VHOST && sudo nginx -t && sudo systemctl reload nginx'"
}
trap al_salir EXIT

# ---------------------------------------------------------------------------
# 0a. Que se publique un COMMIT, no el árbol sucio (directiva 31).
#     ÁMBITO = REPO ENTERO, no sitio/. Lo cazó la revisión del 2026-10-12: el
#     paso 1 construye el WASM con `construir.sh`, que compila el crate `tunjo`
#     ENTERO (verificador-wasm depende de tunjo por `path = ".."`). Si la guarda
#     solo mirara sitio/, un cambio sin commitear en verificador-wasm/ o en el
#     src/ de tunjo se publicaría en el binario y el SHA impreso MENTIRÍA sobre
#     su procedencia — el agujero que la D31 cierra, y peor en una herramienta
#     forense. Con un build de por medio, «limpio» = «insumos del build limpios».
# ---------------------------------------------------------------------------
decir "Comprobando que se publica un commit (ámbito: repo entero)"
if ! SUCIO="$(git -C "$REPO" status --porcelain 2>&1)"; then
  echo "ABORTA: no se pudo preguntar a git si el repo está limpio."
  echo "Eso NO es «está limpio»: es que la guarda no llegó a mirar."
  echo "$SUCIO" | sed 's/^/    /'
  exit 1
fi
if [ -n "$SUCIO" ]; then
  echo "ABORTA: el repo tiene cambios sin commitear, y el WASM se construye del"
  echo "árbol, no del commit. Commitea antes de publicar:"
  echo "$SUCIO" | sed 's/^/    /'
  echo
  echo "Si de verdad quieres publicar el árbol sucio: PERMITIR_SUCIO=1 $0 ${1:-}"
  [ "${PERMITIR_SUCIO:-0}" = "1" ] || exit 1
  echo "  PERMITIR_SUCIO=1: se publica el árbol sucio, y queda dicho aquí."
fi
SHA="$(git -C "$REPO" rev-parse --short HEAD)"
echo "  se publica $SHA$([ -n "$SUCIO" ] && echo ' + cambios sin commitear')"

# ---------------------------------------------------------------------------
# 0b. DNS: A correcto Y AAAA AUSENTE (ver nota 2). Dos vías, porque son dos
#     preguntas: «¿resuelve el MUNDO?» (decide si se despliega) y «¿resuelve
#     ESTA máquina?» (decide si el curl final sirve). «No hay» y «no se pudo
#     preguntar» NO pueden verse igual (directiva 30): `doh` las separa por
#     código de salida.
# ---------------------------------------------------------------------------
doh() {  # doh <nombre> <A|AAAA> → imprime direcciones; ≠0 si no se pudo consultar
  local r
  r="$(curl -s -H 'accept: application/dns-json' --max-time 10 \
       "https://cloudflare-dns.com/dns-query?name=$1&type=$2")" || return 1
  case "$r" in *'"Status":'*) ;; *) return 1 ;; esac
  echo "$r" | { grep -oE '"data":"[0-9a-fA-F.:]+"' || true; } | cut -d'"' -f4
}
resolver_a() {  # imprime «<ip> <vía>»; vacío si ninguna vía lo ve
  local d="$1" ip
  ip="$(dig +short A "$d" 2>/dev/null | tail -1)"
  [ -n "$ip" ] && { echo "$ip local"; return; }
  ip="$(doh "$d" A | head -1)" || return 0
  [ -n "$ip" ] && echo "$ip DoH"
}

decir "Comprobando el DNS"
RESUELVE_LOCAL=1
lectura="$(resolver_a "$DOMINIO")"
ip="${lectura%% *}"; via="${lectura##* }"
[ "$via" = "local" ] || RESUELVE_LOCAL=0
if [ "$ip" != "$ESPERADO" ]; then
  echo "ABORTA: «$DOMINIO» resuelve a «${ip:-nada}», no a $ESPERADO."
  echo "OVH tarda hasta 24 h en propagar. La señal de que ya está es que"
  echo "«dig +short @1.1.1.1 $DOMINIO» devuelva $ESPERADO."
  exit 1
fi
if ! v6="$(doh "$DOMINIO" AAAA | head -1)"; then
  echo "ABORTA: no se pudo consultar el AAAA de «$DOMINIO» por DoH."
  echo "No es «no tiene AAAA»: es que la compuerta no llegó a preguntarlo."
  exit 1
fi
if [ -n "$v6" ]; then
  echo "ABORTA: «$DOMINIO» tiene un registro AAAA ($v6)."
  echo "IPv6 no tiene servidor por defecto aquí: las visitas por IPv6 caerían en"
  echo "el vhost de OTRO sitio, con error de certificado. Quita el AAAA en OVH,"
  echo "o pon «listen [::]» en 000-default primero."
  exit 1
fi
printf '  %-30s %s   (sin AAAA, visto por %s)\n' "$DOMINIO" "$ip" "$via"

RESOLVE=()
if [ "$RESUELVE_LOCAL" = "0" ]; then
  echo
  echo "  AVISO: esta máquina no resuelve el nombre (DNS de la red interceptado)."
  echo "  El mundo sí —comprobado por DoH— y el despliegue sigue. La verificación"
  echo "  final usará «curl --resolve», así que medirá el SERVIDOR y NO el DNS."
  RESOLVE+=(--resolve "$DOMINIO:443:$ESPERADO" --resolve "$DOMINIO:80:$ESPERADO")
fi

# ---------------------------------------------------------------------------
# 1. CONSTRUIR el verificador WASM desde fuente (los artefactos están
#    git-ignored: se regeneran, no se versionan). Reproducible y offline.
# ---------------------------------------------------------------------------
if [ "$MODO" != "vhost" ]; then
  decir "Construyendo el verificador WASM desde fuente"
  bash "$REPO/verificador-wasm/construir.sh"
  for a in verificador/verificador_wasm_bg.wasm verificador/verificador_wasm.js; do
    [ -f "$SITIO/$a" ] || { echo "ABORTA: el build no dejó $a"; exit 1; }
  done
fi

# ---------------------------------------------------------------------------
# 2. Que estén los archivos de la lista blanca, ANTES de tocar el servidor.
# ---------------------------------------------------------------------------
decir "Comprobando lo que se va a publicar"
for f in "${PUBLICOS[@]}"; do
  [ -e "$SITIO/$f" ] || { echo "ABORTA: falta $f"; exit 1; }
  if [ -d "$SITIO/$f" ]; then
    printf '  %-26s dir  %s archivos\n' "$f/" "$(find "$SITIO/$f" -type f | wc -l)"
  else
    printf '  %-26s %s bytes\n' "$f" "$(stat -c%s "$SITIO/$f")"
  fi
done

# ---------------------------------------------------------------------------
# 3. Respaldo con marca de tiempo. Es la vuelta atrás.
# ---------------------------------------------------------------------------
decir "Respaldando lo que hubiera"
ssh "$SERVIDOR" "
  set -e
  if [ -d $RAIZ ]; then
    sudo cp -a $RAIZ $RAIZ.antes-de-$SELLO-$SHA && echo '  copia en $RAIZ.antes-de-$SELLO-$SHA'
  else
    echo '  no había nada: primera publicación'
  fi
  sudo mkdir -p $RAIZ
"

decir "Comparando con lo que ya está"
ssh "$SERVIDOR" "cd $RAIZ && md5sum index.html verificador/verificador_wasm_bg.wasm 2>/dev/null || echo '  (vacío)'"
md5sum "$SITIO/index.html" "$SITIO/verificador/verificador_wasm_bg.wasm"

# ---------------------------------------------------------------------------
# 4. Subir, por MONTAJE INTERMEDIO (lista blanca) y `tar` sobre ssh.
#    rsync NO está instalado en el servidor (medido 2026-08-10, código 12), y el
#    directorio nuevo es lo que hace cierta la lista blanca: lo publicado es, por
#    construcción, exactamente el contenido de un árbol que solo tiene lo de
#    PUBLICOS. Nada que sobre en el servidor sobrevive al `mv`.
# ---------------------------------------------------------------------------
decir "Subiendo"
MONTAJE="$(mktemp -d)"   # lo borra `al_salir`
# EL MONTAJE SE CONSTRUYE POR EL CONJUNTO PERMITIDO, no copiando directorios.
# Lo cazó la revisión del 2026-10-12: `cp -a verificador/ ejemplo/` copiaba los
# directorios ENTEROS, archivos git-ignored incluidos, y la guarda del paso 0a
# (git status sin --ignored) no los ve. Un `*.clave` o `acta*.json` dejado en
# sitio/ejemplo/ (patrones del .gitignore NO anclados: casan a cualquier
# profundidad) saldría publicado ante la audiencia judicial. Por construcción el
# montaje es EXACTAMENTE {archivos rastreados por git bajo la lista blanca} ∪
# {los artefactos del build, por allowlist explícito}: nada ignorado se cuela.
while IFS= read -r rel; do
  mkdir -p "$MONTAJE/$(dirname "$rel")"
  cp "$SITIO/$rel" "$MONTAJE/$rel"
done < <(git -C "$SITIO" ls-files -- "${PUBLICOS[@]}")
for a in "${GENERADOS[@]}"; do
  [ -f "$SITIO/$a" ] || { echo "ABORTA: falta el artefacto del build $a (¿corrió construir.sh?)"; exit 1; }
  mkdir -p "$MONTAJE/$(dirname "$a")"
  cp "$SITIO/$a" "$MONTAJE/$a"
done
# Positivo de control (D30): el montaje NO puede tener nada fuera del conjunto
# permitido. Sin esto, la construcción de arriba "parece" cerrada pero un fallo
# futuro (un glob, un cp de más) volvería a filtrar en silencio.
# LC_ALL=C en las tres: `sort` con locale reordena la puntuación y `comm` compara
# por bytes; si no coinciden, `comm` avisa «no está en orden» y puede DEJAR PASAR
# un extra — el control tiene que discriminar siempre (D33), no casi siempre.
PERMITIDOS="$( { git -C "$SITIO" ls-files -- "${PUBLICOS[@]}"; printf '%s\n' "${GENERADOS[@]}"; } | LC_ALL=C sort -u )"
EN_MONTAJE="$( cd "$MONTAJE" && find . -type f | sed 's|^\./||' | LC_ALL=C sort -u )"
EXTRA="$(LC_ALL=C comm -13 <(printf '%s\n' "$PERMITIDOS") <(printf '%s\n' "$EN_MONTAJE"))"
if [ -n "$EXTRA" ]; then
  echo "ABORTA: el montaje tiene archivos fuera del conjunto permitido:"
  echo "$EXTRA" | sed 's/^/    /'
  exit 1
fi
echo "  montaje = $(printf '%s\n' "$EN_MONTAJE" | grep -c .) archivos, todos en el conjunto permitido"
NUEVA="$RAIZ.nueva-$SELLO"
tar -C "$MONTAJE" -cf - . | ssh "$SERVIDOR" "
  set -e
  sudo rm -rf $NUEVA
  sudo mkdir -p $NUEVA
  sudo tar -C $NUEVA -xf - --no-same-owner
  sudo chown -R root:root $NUEVA
  sudo find $NUEVA -type f -exec chmod 0644 {} +
  sudo find $NUEVA -type d -exec chmod 0755 {} +
"
# El cambio es un `mv` (rename(2)): la ventana sin sitio son microsegundos. El
# respaldo con marca de tiempo del paso 3 es la vuelta atrás.
ssh "$SERVIDOR" "
  set -e
  if [ -d $RAIZ ]; then sudo rm -rf $RAIZ.saliente && sudo mv $RAIZ $RAIZ.saliente; fi
  sudo mv $NUEVA $RAIZ
  sudo rm -rf $RAIZ.saliente
  echo '  publicado:'
  ls -la $RAIZ | sed 's/^/    /'
"

# ---------------------------------------------------------------------------
# 5. Vhost. En --solo-contenido no se toca; en los otros dos, fase 1 (temporal)
#    + fase 2 (definitivo), igual que el modelo.
# ---------------------------------------------------------------------------
if [ "$MODO" = "contenido" ]; then
  decir "Modo --solo-contenido: NO se toca el vhost ni el certificado"
else
if [ "$MODO" = "vhost" ]; then
  decir "Modo --solo-vhost: se reescribe el vhost, sin fase 1 y sin certificado"
  ssh "$SERVIDOR" "
    set -e
    sudo test -f /etc/letsencrypt/live/$DOMINIO/fullchain.pem || {
      echo 'ABORTA: no hay certificado. --solo-vhost no lo emite; usa el modo completo.'
      exit 1
    }
    echo '  certificado presente: el vhost definitivo puede validar'
  "
else
  decir "Fase 1: vhost temporal para el reto"
  if ssh "$SERVIDOR" "test -f /etc/letsencrypt/live/$DOMINIO/fullchain.pem" 2>/dev/null; then
    echo "  AVISO: ya hay certificado, o sea que el kit YA ESTÁ PUBLICADO."
    echo "  Esta fase lo deja INACCESIBLE hasta que termine la fase 2."
    echo "  Si solo querías actualizar el contenido, ya está subido: corta aquí,"
    echo "  o la próxima vez usa  $0 --solo-contenido"
    echo "  Sigo en 10 s; Ctrl-C para parar."
    sleep 10
  fi
  ssh "$SERVIDOR" "sudo tee /etc/nginx/sites-available/$VHOST >/dev/null" <<NGINX
# TEMPORAL: solo para emitir el certificado. Lo sustituye la fase 2.
server {
    listen 80;
    server_name $DOMINIO;
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 404; }
}
NGINX
  ssh "$SERVIDOR" "
    set -e
    sudo ln -sf /etc/nginx/sites-available/$VHOST /etc/nginx/sites-enabled/$VHOST
    sudo nginx -t && sudo systemctl reload nginx
  "

  # El hook de recarga tras renovar es GLOBAL y ya debería existir (lo instaló el
  # despliegue de abogadoisaza). Se reafirma idempotente por si este subdominio
  # se despliega en una máquina donde aún no esté.
  decir "Hook de recarga tras renovar (idempotente, global)"
  ssh "$SERVIDOR" "
    set -e
    sudo tee /etc/letsencrypt/renewal-hooks/deploy/recargar-nginx.sh >/dev/null <<'HOOK'
#!/bin/sh
# Recarga nginx tras renovar CUALQUIER certificado. Sin esto, un linaje emitido
# con \`certonly --webroot\` renueva el archivo y nginx sigue sirviendo el viejo
# en memoria hasta que caduca: el sitio muere a los 90 días sin un solo error.
systemctl reload nginx
HOOK
    sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/recargar-nginx.sh
    sudo test -x /etc/letsencrypt/renewal-hooks/deploy/recargar-nginx.sh
    echo '  hook presente y ejecutable'
  "

  decir "Certificado"
  ssh "$SERVIDOR" "
    set -e
    if sudo test -d /etc/letsencrypt/live/$DOMINIO; then
      echo '  ya existe un linaje'
    else
      sudo certbot certonly --webroot -w /var/www/html -d $DOMINIO \\
        --agree-tos --no-eff-email -m isazajuancarlos@gmail.com --non-interactive
    fi
    sudo test -f /etc/letsencrypt/live/$DOMINIO/fullchain.pem
    san=\"\$(sudo openssl x509 -in /etc/letsencrypt/live/$DOMINIO/fullchain.pem \\
             -noout -ext subjectAltName | tr -d ' ')\"
    echo \"\$san\" | grep -q \"DNS:$DOMINIO\$\\|DNS:$DOMINIO,\" || {
      echo \"ABORTA: el certificado no cubre «$DOMINIO». SAN: \$san\"
      exit 1
    }
    echo '  el certificado cubre el nombre'
  "
fi   # fin rama «modo completo» (fase 1 + hook + certificado)

# ---------------------------------------------------------------------------
# 5b. FASE 2: vhost definitivo. Corre también en --solo-vhost.
#     Se guarda el anterior y se restaura si `nginx -t` sale rojo, para no dejar
#     en sites-enabled una configuración que no valida (los otros sitios
#     caerían en el siguiente arranque / renovación).
# ---------------------------------------------------------------------------
decir "Fase 2: vhost definitivo"
ssh "$SERVIDOR" "sudo cp -a /etc/nginx/sites-available/$VHOST /etc/nginx/sites-available/.$VHOST.previo 2>/dev/null || true"
ssh "$SERVIDOR" "sudo tee /etc/nginx/sites-available/$VHOST >/dev/null" <<'NGINX'
# Kit de tunjo: página + verificador WASM client-side. Subdominio de servicio de
# la práctica jurídica (decisión 0009: herramienta GRATIS que co-marca con
# Xiliux). Vhost y raíz APARTE de abogadoisaza.com: esta CSP ejecuta WASM, la de
# la página jurídica es `default-src 'none'`.
#
# SIN `listen [::]`: en IPv6 el primer bloque del glob absorbe los nombres sin
# vhost, y añadirlo aquí podría robarle nombres a otros sitios. La compuerta del
# paso 0 exige que verificar.abogadoisaza.com NO tenga AAAA.
server {
    listen 80;
    server_name verificar.abogadoisaza.com;
    # El reto de certbot vuelve por aquí cada 60 días, ANTES del redirect: con el
    # 301 delante, el reto acabaría en HTTPS y la renovación fallaría en silencio.
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://verificar.abogadoisaza.com$request_uri; }
}

server {
    listen 443 ssl;
    server_name verificar.abogadoisaza.com;

    root /var/www/verificar.abogadoisaza;
    index index.html;

    ssl_certificate     /etc/letsencrypt/live/verificar.abogadoisaza.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/verificar.abogadoisaza.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # CSP para una página que ejecuta WASM en el navegador, pero NADA de terceros:
    #   script-src 'self' 'wasm-unsafe-eval'  → app.js (externo, no inline) + WASM
    #   connect-src 'self'                     → fetch del .wasm (instantiateStreaming)
    #   style-src 'self' 'unsafe-inline'       → el estilo va inline en index.html
    #   img-src 'self'                         → xiliux-logo.webp local
    # Sin 'unsafe-eval' entero: 'wasm-unsafe-eval' habilita SOLO WebAssembly.
    add_header Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;

    # MIME de WebAssembly. Debian 13 ya mapea .wasm → application/wasm en
    # mime.types; esto lo fija de forma explícita por si acaso (sin ello el
    # navegador rechaza instantiateStreaming con un type incorrecto). SIN
    # `add_header` aquí a propósito: en nginx un `add_header` en el `location`
    # REEMPLAZA a los del `server` (no suma), así que ponerlo dejaría la .wasm sin
    # HSTS ni nosniff. Al no tener ninguno, hereda todos los del server.
    location ~ \.wasm$ {
        default_type application/wasm;
    }

    location / { try_files $uri $uri/ =404; }
}
NGINX
ssh "$SERVIDOR" "
  set -e
  if sudo nginx -t; then
    sudo systemctl reload nginx
    sudo rm -f /etc/nginx/sites-available/.$VHOST.previo
  else
    echo 'ABORTA: nginx -t rechazó el vhost definitivo. Restaurando el anterior.'
    if sudo test -f /etc/nginx/sites-available/.$VHOST.previo; then
      sudo mv /etc/nginx/sites-available/.$VHOST.previo /etc/nginx/sites-available/$VHOST
      sudo nginx -t && echo '  restaurado; la configuración vuelve a validar'
    else
      echo '  no había copia previa; se retira el enlace para no romper el resto'
      sudo rm -f /etc/nginx/sites-enabled/$VHOST
      sudo nginx -t && echo '  la configuración vuelve a validar sin el sitio nuevo'
    fi
    exit 1
  fi
"
fi   # fin del bloque que --solo-contenido se salta

# ---------------------------------------------------------------------------
# 6. Verificar CONTRA EL DOMINIO. Se verifica en LOS DOS modos.
# ---------------------------------------------------------------------------
decir "Comprobando desde fuera"
CURL=(curl -s -o /dev/null --max-time 10 ${RESOLVE[@]+"${RESOLVE[@]}"})
[ "$RESUELVE_LOCAL" = "0" ] && echo "  (con --resolve: esto mide el SERVIDOR, no el DNS)"
printf '  %-40s %s\n' "https://$DOMINIO/" "$("${CURL[@]}" -w '%{http_code} %{redirect_url}' -L "https://$DOMINIO/")"

echo
echo "  Lo que tiene que estar (y su content-type):"
printf '    %-34s %s\n' "/app.js"   "$("${CURL[@]}" -w '%{http_code} %{content_type}' "https://$DOMINIO/app.js")"
printf '    %-34s %s\n' "/verificador/verificador_wasm_bg.wasm" \
  "$("${CURL[@]}" -w '%{http_code} %{content_type}' "https://$DOMINIO/verificador/verificador_wasm_bg.wasm")"
printf '    %-34s %s\n' "/xiliux-logo.webp" "$("${CURL[@]}" -w '%{http_code} %{content_type}' "https://$DOMINIO/xiliux-logo.webp")"

echo
echo "  Y lo que NO puede estar (404):"
for f in desplegar.sh .gitignore; do
  [ -e "$SITIO/$f" ] || { echo "    OJO: «$f» ya no existe; este 404 no mide nada"; continue; }
  printf '    %-34s %s\n' "/$f" "$("${CURL[@]}" -w '%{http_code}' "https://$DOMINIO/$f")"
done

echo
echo "  Que los otros sitios sigan vivos:"
for u in https://abogadoisaza.com/ https://xiliux.com/ https://medico.xiliux.com/ \
         https://informes.xiliux.com/ https://inventario.xiliux.com/ https://chasqui.xiliux.com/; do
  printf '    %-36s %s\n' "$u" "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$u")"
done

if [ "$MODO" = "contenido" ]; then
  echo
  echo "  (renovación no comprobada: --solo-contenido no toca certificado ni vhost)"
else
  echo
  echo "  Que la renovación quede programada Y RECARGUE:"
  ssh "$SERVIDOR" "
    systemctl list-timers 'certbot*' --no-pager | head -3
    echo
    if sudo test -x /etc/letsencrypt/renewal-hooks/deploy/recargar-nginx.sh; then
      echo '  hook de recarga: presente y ejecutable'
    else
      echo '  OJO: NO hay hook de recarga. El cert se renovará en disco y nginx'
      echo '  seguirá sirviendo el viejo hasta que caduque.'
    fi
    echo
    sudo certbot renew --dry-run --run-deploy-hooks --cert-name $DOMINIO 2>&1 | tail -5
  "
fi

decir "Hecho."
echo "Vuelta atrás:"
echo "  ssh $SERVIDOR 'sudo rm /etc/nginx/sites-enabled/$VHOST && sudo nginx -t && sudo systemctl reload nginx'"

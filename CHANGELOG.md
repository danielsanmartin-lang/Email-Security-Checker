# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es/1.1.0/)
y [Versionado Semántico](https://semver.org/lang/es/).

## [Sin publicar]

### Calidad

- **El test de integración deja de mezclar casos.** `document` y la URL sobreviven entre
  tests, y despachar `DOMContentLoaded` reactivaba las instancias de `bootstrap.js` de los
  tests anteriores: cada submit lo atendían todas, cada una con su copia de los ajustes, y
  pintaba la que terminara la última. De ahí un fallo intermitente bajo `--coverage`. Ahora
  `bootstrap.js` exporta `init()`, que devuelve un `dispose()`, y el test la llama a mano con
  la URL limpia; en el navegador se sigue invocando en `DOMContentLoaded`. El test del ajuste
  MTA-STS vuelve a comprobar el panel pintado, dos casos nuevos vigilan el aislamiento y
  `bootstrap.dom.test.js` cubre el arranque real en `DOMContentLoaded`. Tests: 528 → **531**.

## [4.0.0] - 2026-09-23

Dos cambios de fondo. El análisis DMARC se adapta a **RFC 9989, 9990 y 9991** (DMARCbis),
publicados en mayo de 2026, que sustituyen a RFC 7489. Y la puntuación se rediseña: la
anterior mezclaba cosas que no se pueden sumar, y daba notas bajas a dominios que un receptor
protege de verdad. La 3.4.0 nunca llegó a publicarse: su contenido está aquí.

### ⚠️ Cambio incompatible: nueva puntuación

La nota deja de ser una suma de todo lo que se ve en el DNS. Ahora contesta a una sola
pregunta: **¿puede alguien poner este dominio en el From de un correo y que llegue?** El
transporte se evalúa aparte.

- **Dos ejes.** El anillo y la letra son la **protección contra suplantación**: DMARC 50,
  SPF 20, DKIM 20 e informes 10. La **seguridad del transporte** (MTA-STS 40, TLS-RPT 15,
  DNSSEC 25 y DANE 20) sale en una pastilla aparte, y solo se evalúa si el dominio recibe
  correo. Un nombre sin MX, o con Null MX, sale como "No aplica".
- **Nivel en vez de postura:** Protegido, Parcial o Suplantable. La postura "Fuerte" exigía un
  gateway detectable, MTA-STS verificado y `-all`: ninguno de los 24 dominios medidos llegaba.
- **Sin enforcement la nota no pasa de 45 (D):** con `p=none` cualquiera suplanta el dominio,
  por bien que esté el resto.
- **A+ exige evidencia completa:** reject en todos los niveles, SPF y DKIM evaluados y al
  máximo, e informes. Lo que no se puede verificar desde fuera no resta, pero limita a A (94).
  El desglose muestra la suma sin topes y dice cuándo y por qué se ha aplicado uno.
- **`~all` vale lo mismo que `-all` si DMARC aplica política** (RFC 9989 §7.1). Sin
  enforcement, `-all` sigue valiendo más.
- **Una clave DKIM revocada** (`p=` vacío) es un hallazgo informativo, no un fallo: retirarla
  así es lo correcto. Si solo aparecen claves revocadas, DKIM queda sin evaluar.
- **Un nombre que no envía correo** (sin MX ni SPF) cubierto por DMARC en enforcement no se
  penaliza por no tener SPF. Se recomienda `v=spf1 -all` y Null MX.
- **BIMI sale de la nota:** es marca, no seguridad. Si el dominio no publica BIMI, se consulta
  el del dominio organizativo, que es lo que hace el receptor.
- **MTA-STS publicado pero no descargado** cuenta como "publicado, sin verificar" (25 de 40),
  no como ausente.

Medido sobre los mismos dominios, solo por DNS y con los ajustes por defecto:

| Dominio | v3.3.0 | v4.0.0 | Transporte |
|---|---|---|---|
| telefonica.com | 54 D (débil) | 45 D · Suplantable | F |
| support.apple.com | 32 F (débil) | 94 A · Protegido | No aplica |
| apple.com | 65 C | 93 A · Protegido | F |
| iberdrola.es | 54 D | 94 A · Protegido | F |
| santander.com | 60 C | 94 A · Protegido | F |
| github.com | 61 C | 93 A · Protegido | F |
| google.com | 81 A | 94 A · Protegido | D |
| paypal.com | 73 B | 94 A · Protegido | F |
| mailbox.org | 93 A+ | 94 A · Protegido | A |
| posteo.de | 63 C (débil) | 26 F · Suplantable | A |
| ncsc.gov.uk | 87 A | 100 A+ · Protegido | D |

posteo.de baja porque publica `p=none`: su transporte es ejemplar, pero su dominio se puede
suplantar. telefonica.com, igual. support.apple.com sube porque `sp=reject` de apple.com lo
protege aunque no tenga MX ni SPF propios.

### DMARCbis: qué política cuenta

Durante la transición conviven receptores de las dos normas: a 23/09/2026, dmarcdkim.com
contabiliza 114 de 4.958 emisores de informes (un 2,3 %) con el formato nuevo. GMX, WEB.DE y
mail.com ya lo usan al 100 %; Google, Microsoft y Yahoo, todavía no. Por eso la nota es
**conservadora**: cuenta la política más débil que aplicaría alguna de las dos generaciones de
receptores.

- **`t=y` (modo prueba, RFC 9989 §4.7):** la política cuenta un nivel menos (reject →
  quarantine, quarantine → none).
- **`pct=0`:** cuenta como la política inferior, que es lo que aplican los receptores RFC 7489
  (§6.6.4). Un pct parcial resta 5 puntos.
- **Subdominios que heredan la política:** se puntúan con `sp` (RFC 9989 §4.10.1), no con `p`.
  En el propio dominio organizativo, `sp=none` resta 12 y `np=none`, 6.
- **quarantine y reject son enforcement** (RFC 9989 §3.2.9): 46 y 50 puntos. §7.4 desaconseja
  reject en dominios cuyos usuarios escriben a listas de correo.
- **Valores de política no válidos** (§4.10.1): el registro cuenta como `p=none`, o sin efecto
  si no hay ningún rua válido. `p=Reject` en mayúsculas, que la ABNF admite, puntúa como reject.
- **Varios registros DMARC en el mismo nombre** se descartan todos (§4.10): no cuentan ni su
  política ni sus `rua`.
- **Informes:** exigen un `rua` válido. No cuentan `rua=dmarc@dominio` sin `mailto:` ni tener
  solo `ruf`. Un destino externo sin autorizar (RFC 9990 §4) resta 4.
- **SPF con `redirect=`:** el `all` efectivo sale del registro de destino (antes, un falso
  "sin all").
- **Varios registros SPF, un include roto, más de dos consultas vacías, más de 10 lookups o un
  mecanismo con errata** (`inlcude:`, `-all;`) son PermError: 0 puntos.
- **MTA-STS en `mode: testing`** deja de ser un error rojo: es un aviso con 15 de 40.
- **DNSSEC:** puntúa solo si la zona valida (flag AD). DANE solo se evalúa si valida la zona
  del dominio, y solo puntúa si también validan los TLSA.

### Añadido

- **DNS Tree Walk (RFC 9989 §4.10) sobre DoH.** `discoverDmarcPolicy()` descubre la política
  aplicable y el dominio organizativo sin Public Suffix List y sin backend. Entiende `psd=n` y
  `psd=y`, y marca la búsqueda como incompleta si un nivel no responde. En un dominio típico
  cuesta una consulta más (`_dmarc.<tld>`), que queda en caché.
- **`js/dmarc.js`**, un módulo puro con la semántica de RFC 9989 y su convivencia con RFC 7489.
- **Etiquetas `t` y `psd`** en el panel y en el informe, más un bloque "Política que se aplica a
  este dominio" que muestra la herencia y lo que aplica cada generación de receptores.
- **Hallazgos nuevos:** `pct` y `ri`/`rf` eliminados, `fo` sin `ruf`, etiquetas desconocidas,
  `psd`, `rua` sin esquema, `p=none` sin `rua` y la nota de §7.4 para reject.
- **MTA-STS comprobado por DNS:** si `mta-sts.<dominio>` no resuelve, la política está rota para
  cualquier MTA. Es un hallazgo de error que se obtiene sin mandar ni una petición al dominio.
- **El MX de Exchange Online con DNSSEC/DANE** (`*.x-v1.mx.microsoft`) se reconoce como
  Microsoft 365; antes salía como "MX externo no identificado".
- **Claves DKIM sin `v=DKIM1`**: esa etiqueta es opcional según RFC 6376 §3.6.1.

### Privacidad

- **Nuevo ajuste "Descargar la política MTA-STS", apagado por defecto.** Esa petición es CORS:
  deja en los registros del prospecto la IP del auditor y el `Origin` de la app. Sin ella,
  MTA-STS se comprueba por DNS.
- **Nuevo ajuste "Cargar logotipos BIMI", encendido por defecto.** Una imagen no envía
  `Origin` y la página va sin Referer, así que el servidor del logo (casi siempre una CDN) solo
  ve la IP. Apagado, el logo se carga con un clic.
- **Google DoH con `edns_client_subnet=0.0.0.0/0`:** la red del auditor ya no llega a los DNS
  autoritativos del prospecto.
- **`<meta name="referrer" content="no-referrer">`** en la página.

### Corregido

- **Inyección de HTML en el informe exportado** (PDF, Word y Google Docs). `p`, `sp` y `pct` del
  registro DMARC, y la política del resumen, entraban sin escapar, así que un registro con
  marcado (`p=<img src=https://…>`) quedaba insertado en el informe. Hay un test de regresión
  en `render.dom.test.js`, comprobado contra el código anterior: allí falla.
- **Verificación de destinos externos** (RFC 9990 §4): ahora se antepone el dominio donde se
  encontró la política. En los subdominios que la heredaban salía un falso "no autorizado".
- **Heurística de dominio raíz:** una marca de tres letras o menos bajo un ccTLD (ine.es,
  dhl.de, abc.es) ya no se toma por sufijo público. Provocaba MX propios presentados como
  "externos", DMARC sin heredar y destinos propios "no autorizados".
- **Hospedaje:** un TLSA en un MX de Microsoft 365 ya no cuenta como indicio de servidor propio.
- **Analizador de cabeceras:** `sophosmail.com` hacía pasar por simulación de Sophos Phish Threat
  cualquier correo filtrado por el gateway Sophos Email.
- **Awareness:** usa el árbol SPF del análisis principal, así que su PermError ya no contradice
  al panel SPF. Además, los selectores DKIM de cada vendor se sondean en paralelo.
- **`parseSPF`:** reconoce mecanismos en mayúsculas, `a/24` y `mx//64` (antes desaparecían de la
  tabla) y `exp=`. `redirect=` se ignora si el registro tiene `all`.
- **Contaminación del prototipo** desde un JSON de firmas (`__proto__`).
- **Service worker:** ya no guarda un 404 o un 5xx como página de inicio sin conexión.
- **Panel de MTA-STS:** el cuerpo de la política ya no se escapa dos veces.

### Textos

- Las citas pasan a RFC 9989/9990: herencia (§4.10.1), destinos externos (RFC 9990 §4) y
  registros múltiples (§4.10).
- El texto de `pct` decía que el resto del correo "se entrega sin aplicar la política". Es falso
  también con RFC 7489: ese resto recibe la política inferior.

### Calidad

- Tests: 408 → **528**, con casos de calibración sacados de dominios reales. Cobertura global
  del 91,8 %, con un umbral propio para `js/dmarc.js`.
- La CI pasa a Node 22 y 24: Node 20 dejó de tener soporte en abril de 2026.

## [3.3.0] - 2026-09-17

### Añadido

- **Detección de hospedaje del correo: nube, híbrido u on-premise** (`js/mailHosting.js`).
  La herramienta deducía el "proveedor de correo" del registro MX, pero **el MX es el filtro
  de entrada, no la plataforma de buzón**. Con un SEG delante (Proofpoint, Mimecast,
  Hornetsecurity, IronPort) el MX tapa por completo lo que hay detrás: telefonica.es y
  mercadona.es tienen ambos un gateway en el MX y, sin embargo, una tiene los buzones en
  Microsoft 365 y la otra en su propio centro de datos. El panel de proveedor pasa a mostrar
  tres filas —filtro de entrada, plataforma de buzón y hospedaje— cada una con su evidencia.
- **Consumidor para el `type: 'self'` de `identifyMX`.** Ese valor se calculaba desde
  siempre y no lo leía nadie: cuando el MX pertenecía al propio dominio, `provider` se
  quedaba a `null` y la interfaz decía "proveedor no identificado". El caso on-premise, que
  es el más interesante de detectar, se caía por un agujero del código.
- **Tres sondas DNS nuevas** en `js/api.js`, todas sobre la capa DoH que ya existía —sin
  CORS, sin backend y sin tocar la CSP:
  - `getAutodiscover()` resuelve `autodiscover.<dominio>` conservando el CNAME. Es el mejor
    indicador externo de dónde están los buzones. Distingue "no existe" de "no se pudo
    consultar": un fallo transitorio de DNS no debe leerse jamás como ausencia de registro.
  - `getIpIntel()` perfila una IP con el mapeo IP→ASN de Team Cymru (que se sirve por DNS) y
    su PTR. Cuando una empresa anuncia sus propios rangos, el ASN lleva literalmente su
    nombre: `AS_INDITEX`, `ASMERCADONA`.
  - `getDkimSelectorChain()` conserva el CNAME que `getDKIM` descarta. En Microsoft 365 ese
    destino apunta al tenant (`…onmicrosoft.com`) y hasta revela su nombre.
- **`reverseIpForDns()`** generaliza la inversión de IP que hasta ahora solo usaban las RBL.
- **Diccionarios de ASN** (`cloud_asns`, `cdn_asns`, `hoster_asns`), destinos de CNAME de
  plataforma y pesos de las señales, en `js/knowledge.js` (KB 3.1.0).
- **El informe exportado** incluye el hospedaje, con su evidencia y sus salvedades.

### Notas de diseño

- **La clasificación no toca la puntuación.** On-premise no es inseguro per se; penalizarlo
  sería una afirmación que los datos no sostienen, y el mismo error de categoría —confundir
  infraestructura con control de seguridad— que este cambio viene a corregir.
- **`undetermined` es un resultado de primera clase.** ugr.es no da señales suficientes y se
  presenta como "no determinable con DNS público", sin insignia y sin porcentaje: un "0%"
  junto a "no determinable" sugeriría una medición donde no hay ninguna.
- **Varias señales pesan por debajo del umbral a propósito**, para que no puedan decidir
  solas. El ASN de Microsoft cubre Exchange Online y también las máquinas Azure donde
  alguien corre su propio Exchange; un MX del propio dominio puede ser un CNAME a un hosting.
- **Tres técnicas descartadas**, documentadas en el módulo para que no se reintroduzcan:
  sondear `<dominio>.mail.protection.outlook.com` (falso positivo sistemático: devuelve
  NOERROR para dominios de Google Workspace); leer la ausencia de `autodiscover` como
  indicio de on-premise (es un protocolo de Microsoft, Workspace no lo publica nunca); y
  leer los literales `ip4:` del SPF como indicio de buzones locales (hablan del relé de
  salida — telefonica.es publica 17 rangos propios y tiene los buzones en M365).

### Corregido

- **El panel de proveedor decía "no identificado" con un gateway delante.** La fila del
  filtro de entrada ahora muestra el SEG que el MX confirma, en vez de dejar en blanco una
  pregunta que sí tenía respuesta.

### Verificación

Las reglas se calibraron contra medidas en vivo y los tests unitarios usan esas medidas
como fixtures: telefonica.es → nube; inditex.com y congreso.es → híbrido (con tenant);
mercadona.es y csic.es → on-premise; ugr.es → no determinable; cabify.com, glovoapp.com y
wallapop.com → nube (Workspace).

## [3.2.0] - 2026-09-05

### Añadido

- **Alemán como tercer idioma de la interfaz.** Las 472 claves del diccionario traducidas
  (`de` en `js/i18n.js`), no un subconjunto: hallazgos de la puntuación, tooltips de SPF y
  DMARC, panel de concienciación, visor de informes RUA, ajustes, modales y el informe
  exportado. El selector de la cabecera pasa a tres entradas (ES / EN / DE) con la bandera
  alemana como SVG propio, igual que las otras dos: sin peticiones a terceros.
- **Test de paridad del diccionario** (`js/i18n.test.js`). El README ya afirmaba que existía
  y no era cierto. Con dos idiomas una clave que faltase pasaba desapercibida —deja el hueco
  en blanco, no rompe nada—; con tres, el descuido es cuestión de tiempo. Verifica que los
  tres idiomas tengan el mismo juego de claves, ninguna cadena vacía, los mismos marcadores
  de posición (`{policy}`, `{n}`, `{selectors}`…) y las mismas categorías.

### Cambiado

- **El locale de fechas y horas se resuelve en `lang.js`**, no con un ternario `es/en`
  repetido en `export.js` y `summaryPanel.js`. Con un tercer idioma ese ternario habría
  dado formato estadounidense a los informes en alemán. Ahora `getLocale()` mapea
  `es→es-ES`, `en→en-US`, `de→de-DE`.
- **`getLanguage()` valida el idioma guardado** contra `SUPPORTED_LANGS` y cae a español si
  encuentra otra cosa. Antes, un valor inesperado en `localStorage` dejaba la interfaz sin
  traducir en lugar de degradar a un idioma válido.
- **La bandera del botón se resuelve por mapa** (`FLAG_SVG[lang]`) en vez de un `if/else`
  que asumía dos idiomas y habría enseñado la del Reino Unido al elegir alemán.

### Notas

- Quedan fuera tres cadenas que tampoco están en inglés y que no vienen del diccionario:
  las notas de los *fingerprints* de concienciación y algún nombre de servicio de la base
  de conocimiento (ambos en español en sus ficheros de datos) y el mensaje de error del
  descargador de MTA-STS (en inglés en el código).

## [3.1.1] - 2026-08-28

### Cambiado

- **El desglose de la puntuación viene desplegado.** La nota sola no dice nada accionable;
  el desglose por categorías es lo que se lleva a la conversación, así que tenerlo detrás
  de un clic lo escondía justo a quien lo necesita. La flecha ahora sirve para **ocultarlo**,
  y la etiqueta alterna entre "Ocultar desglose" y "Ver desglose". El cambio de etiqueta se
  hace moviendo el `data-i18n`, no solo el texto: así un cambio de idioma la retraduce en el
  estado en el que esté en vez de restaurar la cadena del HTML.
- **Modal del selector DKIM, reescrito para preventa.** Decía *"solo pídele: «Por favor,
  envíame un correo de prueba desde tu cuenta corporativa»"*. A un cliente potencial no se
  le pide un correo porque sí. Ahora parte de lo que ya se tiene: *"Si esa organización te
  ha enviado algún correo alguna vez —una respuesta, una convocatoria de reunión, un hilo
  cualquiera—, ya tienes el dato en tu bandeja"*. El apartado pasa a llamarse
  **"El truco del Email"**.

### Eliminado

- **El "truco" de preguntar al departamento de TI** del prospecto qué selectores DKIM tiene
  activos. Esa llamada no se va a hacer: quedaría mal.
- **El párrafo del "superpoder de emergencia"** (el ejemplo del selector `envios2026`).
  Describía un escenario de soporte a un cliente ya firmado, que no es el uso real de la
  herramienta.

## [3.1.0] - 2026-08-28

Esta versión parte de una auditoría real de `gruporamos.com` y de una constatación sobre
cómo se usa la herramienta: se audita el dominio de un TERCERO, antes de hablar con él.
Nunca se va a tener acceso privilegiado a ese dominio ni un correo suyo.

### Añadido

- **Límite de concurrencia en la capa DNS (6 consultas simultáneas).** Un análisis dispara
  ~116 consultas DoH y salían en picos de **42 a la vez**. Los servidores autoritativos
  pequeños responden SERVFAIL a una parte *aleatoria* de esa ráfaga, y el resolver público
  lo reenvía: la consulta se perdía aunque el registro existiera. Medido en
  `gruporamos.com` (`ns33/ns34.worldnic.com`), donde el subconjunto que fallaba cambiaba en
  cada pasada. Contra la intuición, **el análisis salió más rápido**: la ventana de
  consultas DoH baja de **3095 ms a 782 ms**, porque cada SERVFAIL costaba antes una cadena
  completa de tres resolvers. `google.com` mantiene su nota (81) y su número de consultas.
- **Un reintento ante SERVFAIL**, con 300 ms de espera. Solo ante SERVFAIL (RCODE 2), que
  es un "no he podido" transitorio. **REFUSED (RCODE 5) no se reintenta**: es una negativa
  deliberada — política, RPZ, o una DNSBL que rechaza las consultas que le llegan vía
  resolver público, caso habitual en `checkRBL` — y volver a preguntar da lo mismo.
  Tampoco se reintenta un fallo de red (el problema es local) ni con resolver propio.
- **Corte por zona ya demostrada caída.** Si el reintento de una zona también falla, el
  resto de sus nombres se rinde a la primera durante 30 s. Sin esto, un dominio con el DNS
  roto se llevaba **+5,1 s** de reloj: el detector de awareness sondea 17 selectores DKIM
  *en serie* y cada uno pagaba su espera.
- **Estado del sondeo en el detector de awareness** (`dnsIncomplete`, `dnsFailedQueries`),
  con aviso en el panel y en el informe exportado.

### Corregido

- **El selector DKIM se veía con su ajuste apagado.** `applyToolVisibility()` ponía
  `el.hidden = true` correctamente, pero el atributo `hidden` solo trae un `display:none`
  de la hoja del navegador y `.dkim-toggle-container { display: flex }` lo pisaba (misma
  especificidad, más abajo en el fichero). Se añade `[hidden] { display: none !important }`.
  Solo afectaba a esta herramienta: `rua-section` y `awareness-header-tool` no declaran
  `display`. El test que ya existía no lo detectó porque jsdom no aplica la hoja de
  estilos: comprobaba `el.hidden === true`, que siempre fue cierto.
- **Un SERVFAIL en el detector de awareness era un falso negativo silencioso.** `_doh()`
  capturaba el error y devolvía `{ Answer: [] }`, indistinguible de "consultado y no hay
  nada": un dominio con el DNS caído salía como "no usa ninguna plataforma de awareness".
  Preparando una visita comercial, ese falso negativo se toma por una respuesta.
- **El panel pedía algo imposible en una auditoría de terceros.** Decía *"Para confirmarlo
  hace falta una cabecera de un correo de simulación recibido"* y *"Pega las cabeceras de
  un correo de simulación abajo"*. Nunca se va a tener un correo de simulación de un
  tercero. Peor: el segundo mensaje se emitía **incondicionalmente**, también con el
  analizador de cabeceras apagado (lo está por defecto, así que señalaba a un panel
  invisible) y **también en el PDF exportado**, donde no existe ningún "abajo". Ahora el
  texto enuncia el techo real del DNS —de Microsoft AST no puede deducirse *ni su presencia
  ni su ausencia*— y la mención al analizador solo aparece si esa herramienta está activada;
  en el PDF, nunca.
- **El badge de awareness se contradecía a sí mismo:** rotulaba "Sin evidencia DNS" mientras
  listaba señales indirectas justo debajo. Pasa a cuatro estados reales (detectados /
  señales indirectas / sondeo incompleto / sin evidencia) y deja de llevar los idiomas
  incrustados en el renderizador.

### Cambiado

- **El mensaje de selectores DKIM sin comprobar.** Era *"Errores de red en selectores:
  smg2, mail, mimecast20190707, …"* — una lista de nombres crudos, en rojo de error, que no
  decía ni qué había pasado ni qué hacer, y que describía un "no evaluable" como si fuera un
  fallo del dominio. Ahora se enuncia agregado ("N de M sin comprobar"), distingue la causa
  (**SERVFAIL de la zona auditada** vs. **fallo de red nuestro**), va en ámbar y los nombres
  quedan en un desplegable.
- **El SERVFAIL de la zona pasa a ser un hallazgo del informe.** Que los NS autoritativos de
  un dominio fallen bajo carga afecta a su entregabilidad y a cualquier comprobación
  automática que le haga un tercero: es un dato sobre ese dominio, no ruido de la
  herramienta. **No toca la nota** — la muestra depende de nuestra propia ráfaga de
  consultas, así que penalizar por ella no sería defendible.

### Notas

- Tests: 308 → **326**. Entre ellos, dos de regresión de *deadlock* del semáforo
  (recursión del árbol SPF y sondas void A→AAAA encadenadas), verificados rompiendo el
  invariante a propósito: sin el arreglo se cuelgan y saltan por timeout. Cobertura 89,1 %.

## [3.0.1] - 2026-08-28

### Corregido

- **Se veían etiquetas HTML como texto** en las notas del detector de awareness y en el panel
  de DNS Avanzado (`…apunte a infra del vendor.</li><li>Solo…`). Al convertir los paneles al
  helper `html``​` en 3.0.0 se transformaron los fragmentos exteriores, pero los que quedaban
  **anidados** como plantilla plana siguen devolviendo un string y el helper los escapa.
  Afectaba a más sitios de los visibles a simple vista: en DNS Avanzado se interpolaban cuatro
  acumuladores enteros (TLS-RPT, proveedor DNS, SRV y DANE), así que esos bloques se veían
  como marcado completo.
- **Inyección de HTML en el panel de awareness.** Aquella misma conversión borró los
  `escapeHtml()` del bloque, y `buildAwarenessCard` —que no llegó a convertirse— se quedó sin
  escapar nada. Interpola valores del DNS del dominio auditado, incluido el contenido crudo de
  un registro TXT vía la evidencia `generic_dkim_probe`. El CSP frenaba la ejecución de script,
  pero no la inyección de marcado. La función pasa entera a `html``​`.
- **Falso «destino externo no autorizado» en DMARC.** El RFC 7489 §7.1 exige verificar el
  destino de `rua`/`ruf` solo cuando difiere el **dominio organizativo**; la implementación
  comparaba cadenas exactas, así que a quien manda los informes a un subdominio propio
  (`amazon.com` → `dmarc.amazon.com`) le salía un error rojo diciendo que sus informes se
  descartarían, más una penalización. `extractRootDomain()` se traslada de `analyzer.js` a
  `utils.js` —es una utilidad de nombres de dominio, no lógica de análisis— y se re-exporta
  para no romper imports.

  *Alcance medido* sobre 40 dominios reales (grandes empresas de tecnología, banca y energía):
  afectaba a **2 de los 39** que publican informes (Amazon y Atlassian). La mayoría de las
  organizaciones grandes usa un procesador externo (Agari, Proofpoint, dmarcian, Valimail,
  Redsift, Cisco…), que sí requiere autorización — y **24 de 25** la publican correctamente,
  así que el error rojo solo salta ya donde debe. El caso restante, `santander.com` →
  `gsnetcloud.com`, se comprobó a mano: el dominio de destino existe pero no publica el
  registro, así que sus informes se descartan de verdad. Es un hallazgo legítimo.
- **DANE dejaba de castigarse dos veces.** DANE (RFC 7672) se apoya en DNSSEC: sin la zona
  firmada no es desplegable, así que restar 7 puntos a un dominio que ya pierde 8 por no tener
  DNSSEC cobraba dos veces la misma carencia (15 de los 25 de Transporte). Pasa a «no
  evaluable» y sale del denominador; con DNSSEC activo se sigue exigiendo.

  *Alcance medido* sobre la misma muestra: **34 de 40 dominios (85%)** no tienen la zona
  firmada, así que todos perdían esos 7 puntos por algo que no podían desplegar. Al salir del
  denominador, la nota de cualquiera de ellos sube en torno a un 7% relativo (un 60 pasa a 65,
  un 70 a 75). Es, con diferencia, la corrección de mayor alcance de esta versión.

### Calidad

- Nuevo `escaping.dom.test.js`: renderiza cada panel y comprueba las dos caras de la misma
  moneda —ninguna etiqueta visible como texto con datos limpios, ningún elemento ni manejador
  inyectado con datos que traen marcado—. Verificado que falla si se reintroduce cualquiera de
  los dos fallos. 307 tests en total.

> Efecto medido en `amazon.com`: **56/D → 67/C**, sin errores rojos. Lo que le sigue bajando la
> nota está comprobado por DNS y es correcto: `p=quarantine` en vez de `reject`, sin MTA-STS,
> sin DNSSEC, sin TLS-RPT y clave DKIM de 1024 bits. Los pesos de las categorías no se tocan.

## [3.0.0] - 2026-08-27

### ⚠️ Cambio incompatible: nueva puntuación

El modelo aditivo anterior saturaba: SPF + DMARC `reject` + DKIM ya sumaban 95/100, así que
MTA-STS, DNSSEC, DANE y BIMI no movían la nota y un dominio sin transporte endurecido salía
A+. **Las notas de v3 no son comparables con las de v2.x.**

- Tres categorías con presupuesto propio: **Autenticación 60** (SPF 22 / DMARC 23 / DKIM 15),
  **Transporte 25** (MTA-STS 10 / DNSSEC 8 / DANE 7) e **Higiene 15** (informes DMARC 8 /
  TLS-RPT 4 / BIMI 3).
- El grado está **acotado por el ratio de Autenticación**: DNSSEC, DANE o BIMI ya no
  compensan un dominio suplantable. Con `p=none` o un PermError de SPF no se llega a A.
- Los controles **no evaluables** (DKIM no detectado por selectores comunes, SPF/DMARC sin
  resolver, política MTA-STS inalcanzable por CORS, BIMI declinado) **salen del denominador**
  en vez de contar como cero: se mantiene la regla de que la ausencia de DKIM no penaliza.
- Un control roto sí resta dentro de su categoría (una política inválida puntúa peor que su
  ausencia), pero ninguna categoría baja de 0 ni ningún check supera su presupuesto.
- `scoreCard.breakdown` alimenta el nuevo panel de desglose de la interfaz.

### Motor de análisis
- **SPF**: PermError cuando el destino de un `include`/`redirect` no publica SPF (fallo
  silencioso y frecuente); contaje de **void lookups** (RFC 7208 §4.6.4); mecanismos
  inalcanzables tras `all`; varios `all`; aviso de registro >255 caracteres.
- **MTA-STS**: se contrasta la lista `mx:` de la política con los MX reales (comodín de una
  etiqueta, RFC 8461 §4.1). Una política que no se puede descargar pasa a ser *no evaluable*
  en vez de penalizar como inválida — también en el panel.
- **TLS-RPT**: se valida que los destinos `rua` sean `mailto:` o `https:` (RFC 8460).
- **BIMI**: parseo por etiquetas — certificado **VMC/CMC** (`a=`), declinación explícita
  (`l=` vacío) y aviso si la URL no es HTTPS. El logotipo avisa si no se puede cargar.
- **DKIM**: soporte **Ed25519** (RFC 8463). El umbral de "clave débil <1024 bits" ya solo
  aplica a RSA; antes una Ed25519 se habría marcado como débil. El campo admite varios
  selectores separados por coma.
- **DMARC**: `np` (DMARCbis), `pct` marcado como obsoleto, `fo`/`ri` informativos y aviso
  con más de dos destinos `rua`.

### Nuevo
- **Herramientas avanzadas apagadas por defecto**, con una casilla por herramienta en
  Ajustes: el visor de informes DMARC, el selector DKIM y el analizador de cabeceras exigen
  algo que solo tiene quien administra el correo del dominio (los informes agregados, el
  nombre del selector, una muestra de correo). Se activan y aparecen al instante, sin
  recargar. Un deep-link `?dkim=` se sigue honrando aunque el campo esté oculto.
- **Visor de informes agregados DMARC (RUA)**: arrastra un `.xml`, `.xml.gz` o `.zip` y
  obtén remitentes por IP, volumen y tasas de paso SPF/DKIM/DMARC. Descompresión y parseo
  100% en el navegador, sin red (ni siquiera PTR sobre las IPs).
- **Panel de ajustes**: resolver DoH elegible (Google / Cloudflare / Quad9 / propio, sin
  respaldo público si es propio), proxy CORS público **opt-in y apagado por defecto**,
  refresco forzado que salta la caché de 5 minutos y URL de firmas de awareness.
- **Desglose de la puntuación** por categoría y control, con marca de *no evaluable*.
- **PWA**: manifest e `sw.js` que cachea el app shell. El tráfico externo (DoH, CT logs,
  MTA-STS) **nunca** se cachea: un análisis servido de caché daría un diagnóstico viejo.

### Corregido
- **`google.com` aparecía usando «Cisco Secure Email».** El disparador era el token TXT
  `cisco-ci-domain-verification`, que es la verificación de dominio de **Webex Control Hub**
  («CI» = Common Identity): prueba que alguien dio de alta el dominio en una organización de
  Webex y la propia documentación de Cisco dice que se puede borrar del DNS una vez
  verificado. No dice nada del correo — el MX de Google es suyo. Pasa a categoría
  informativa, sigue visible entre los tokens TXT. Igual con `spycloud-domain-verification`
  (monitorización de credenciales, no un filtro de correo). Regla nueva en el diccionario: un
  token solo es `seg`/`ices` si el producto que verifica es de seguridad de CORREO.
- **Las sospechas de awareness llegaban a confianza «alta» sin una sola prueba.** El score
  era un noisy-OR de todas las señales, así que tres indirectas (0,5 · 0,4 · 0,3) daban 0,79
  → badge «alta», con el aviso de «no confirmado» justo debajo contradiciéndolo. Ahora, sin
  evidencia directa el score se acota a 0,4 («baja»), Certificate Transparency deja de sumar
  y esos vendors salen de `detectedVendors` a una lista `indirectSignals` aparte, que la UI y
  el informe pintan como «señales indirectas (no concluyentes)».
- **Falso positivo sistemático de SEG**: cualquier MX cuyo dominio raíz no coincidiera con
  el analizado se anunciaba como capa de seguridad, con el dominio como "nombre de
  producto" (paypal.com → «paypalcorp.com», acme.com → «acmegroup.net», empresa.es →
  «empresa.com»). Los SEG reales los reconoce el diccionario antes de llegar a ese
  atajo, así que no aportaba ninguna detección: solo afirmaciones insostenibles. Ahora
  esos MX se presentan como **«MX externo no identificado»**, con la pista de si comparte
  nombre de marca con el dominio (probable infraestructura propia) y un botón para
  añadirlo al diccionario.
- El diccionario acepta entradas propias también en la lista **MX** (antes todo iba a la
  de includes SPF, que no se consulta para el correo entrante), con las categorías
  filtradas por lista: a un MX solo se le puede asignar proveedor, SEG o ICES.
- Guardar en el diccionario reventaba si el `<select>` no tenía una opción coincidente.
- La **ausencia** de SEG/ICES ya no fuerza la postura a «débil»: los ICES modernos son
  API-based y no dejan rastro en DNS (punto ciego documentado de la herramienta).
- El service worker servía módulos de caché mientras traía otros de red, y tras un
  despliegue podía mezclar versiones y romper la app. El HTML, el CSS y los `.js` van
  ahora a red primero, con la caché como respaldo sin conexión.
- Los análisis obsoletos ya no pisan al vigente: `runAnalysis` usa un token de ejecución y
  deshabilita el botón mientras trabaja.
- El deep-link se construye con `URLSearchParams` (antes interpolaba dominio y selector sin
  escapar) y el selector DKIM se valida.
- Un `data-tooltip` vacío dejaba visible el tooltip del elemento anterior.

### Privacidad y accesibilidad
- Tipografías **autoalojadas** (92 KB, subsets latin): ninguna petición a Google Fonts.
- **CSP** declarada en `index.html` con `default-src 'self'`, `script-src 'self'`,
  `base-uri 'none'` y `form-action 'none'`. `connect-src` enumera los servicios usados
  y admite además `https:`: la política MTA-STS vive en `mta-sts.<dominio-auditado>`, un
  host que solo se conoce en ejecución y que CSP no puede expresar con comodín.
- Tooltips accesibles: aparecen al enfocar, se cierran con Escape y usan `role="tooltip"`
  con `aria-describedby`. Sus disparadores son enfocables.
- Etiquetas (`sr-only`) para los campos de dominio y selector DKIM; el `aria-label` de la
  región de resultados se traduce.
- Favicon, `meta description` y tarjetas Open Graph/Twitter.

### Arquitectura, calidad y CI
- `js/bootstrap.js` separa el cableado del DOM de la orquestación; `ui.js` pasa de 1088 a
  ~205 líneas y los paneles viven en `js/ui/` (10 módulos).
- Todo el HTML dinámico se construye con el tagged template `html``` (auto-escapado), con
  una **regla ESLint** que prohíbe asignar a `innerHTML` plantillas o concatenaciones crudas.
  Los estilos en línea de la UI pasan a clases.
- `knowledge.js` declara `KB_VERSION`/`KB_UPDATED_AT` y hay tests de esquema de las firmas.
- Nuevo `integration.dom.test.js`: monta `index.html` en jsdom con DoH simulado y recorre el
  flujo completo. Cobertura global 78% → **88%** (`app.js` 36% → 93%); umbrales elevados.
- `pages.yml` publicaba solo `index.html`, `css/*.css` y `js/*.js`: ahora incluye `js/ui/`,
  las fuentes, el manifest, el service worker y el icono, y falla si falta algo del shell.

## [2.6.2] - 2026-07-07

### UI / Accesibilidad
- `role`/`aria-live` en las secciones asíncronas (carga, error, resultados) para
  que los lectores de pantalla anuncien el progreso.
- Los ejemplos de dominio pasan de `<span>` a `<button>` (foco por teclado y
  `:focus-visible`).
- `<html lang>` se sincroniza con el idioma activo.
- Modales con `role="dialog"`, `aria-modal`, cierre con Escape y trampa de foco.
- `--text-muted` aclarado a ratio de contraste ≥ 4.5:1 (WCAG AA).

### Testing / CI / higiene
- ESLint ahora extiende `@eslint/js` recommended (caza `no-dupe-keys`,
  `no-unreachable`, `no-empty`, etc.) y usa el paquete `globals` en vez de una
  lista manual de globales.
- `npm run lint` es bloqueante (`--max-warnings=0`).
- CI: `npm ci` (en vez de `npm install`), caché de npm, matriz Node 20/22 y
  cobertura con umbrales bloqueantes.
- Umbrales de cobertura en `vitest.config.js` (global + por módulo maduro).
- Eliminado `playwright` de devDependencies (no se usaba).
- Añadido `LICENSE` (MIT) y campo `license` en `package.json`.

## [2.6.1] - 2026-07-07

### Exportación y arquitectura
- El informe incluye ahora DNSSEC, DANE/TLSA, SRV, árbol de lookups SPF y
  autorización de destinos DMARC externos (RFC 7489 §7.1).
- PDF unificado: `exportToPDF` imprime el mismo `generateReportHTML()` en un
  iframe oculto, en vez de `window.print()` de la vista viva.
- Traducidas las cadenas del informe que quedaban fijas en inglés; corregido el
  plural «1 detectados» → «1 detectado».
- Banner del informe con color sólido de reserva (Word no soporta gradientes).
- Estado global extraído a `state.js`, rompiendo el ciclo `app.js ↔ export.js`.

## [2.6.0] - 2026-07-07

### Motor DNS (robustez y precisión)
- Degradación resiliente: la fase 1 usa `Promise.allSettled`; solo aborta si
  fallan a la vez MX y el TXT del ápex. SPF/DMARC no resueltos se marcan «no
  disponible» en vez de penalizarse como ausentes.
- Árbol de lookups SPF: resuelve cada nivel en paralelo, cuenta los mecanismos
  con máscara CIDR (`a/24`, `mx/24`) y distingue bucle real de include repetido.
- MTA-STS: no sigue redirects (RFC 8461 §3.3) y usa el código HTTP real del
  proxy.
- Deduplicación de consultas DoH en vuelo.
- Parseo TXT multi-string unificado (`extractTxtValue`) en DKIM/BIMI/awareness.

## [2.5.3] - 2026-07-07

### Robustez
- Herencia DMARC del dominio organizativo (RFC 7489 §6.6.3) para subdominios.
- Reconocimiento de Null MX (RFC 7505).
- FQDN con punto final (`example.com.`) ya no se rechaza.
- La hora del escaneo se fija una vez y no se recalcula al re-renderizar/exportar.

## [2.5.2] - 2026-07-07

### Seguridad
- Corregido XSS por clic en la tabla SPF (onclick inline → `data-` + listener).
- `queryDNS` valida el `Status` DoH: SERVFAIL/REFUSED ya no se reportan como
  «sin registros» ni se cachean.
- RBL: el estado inconcluso se propaga en vez de mostrarse como «Limpio».
- Nuevo workflow de despliegue a GitHub Pages con gate de lint+tests; deja de
  publicarse `graphify-out/` (contenía rutas locales).

## [2.5.1] y anteriores

Ver el historial en `README.md`.

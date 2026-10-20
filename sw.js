/**
 * Service worker: cachea el "app shell" para que la herramienta abra al instante y
 * siga siendo utilizable sin conexión (la interfaz, el visor de informes DMARC y el
 * analizador de cabeceras funcionan enteros en local; el análisis DNS, obviamente, no).
 *
 * Regla de oro: NADA de tráfico externo se cachea. Las consultas DoH, los CT logs y
 * la política MTA-STS van siempre a la red — un análisis servido desde caché daría
 * un diagnóstico de seguridad desactualizado, que es peor que no dar ninguno.
 *
 * Lo que se publica sale de scripts/build.mjs: módulos y CSS con un hash del contenido en
 * el nombre (bootstrap-3KX7Q2LM.js). Un fichero con hash no cambia nunca, así que se sirve
 * de caché sin preguntar a la red. Sin construir (desarrollo local), los ficheros no
 * llevan hash y van a la red primero, como siempre.
 */
const SW_VERSION = 'v5.2.1';

// Los rellena scripts/build.mjs en cada despliegue: un número de secuencia (para ordenar
// las generaciones de caché) y la lista de ficheros publicados. En desarrollo quedan así.
const BUILD_SEQ = 0;
const BUILD_HASH = 'dev';
const PRECACHE = [];

// Prefijo propio: en *.github.io el origen lo comparten todos los proyectos del usuario,
// así que solo se tocan las cachés que empiezan por aquí.
const CACHE_PREFIX = 'esc-shell-';
const CACHE = `${CACHE_PREFIX}${BUILD_SEQ}-${SW_VERSION}-${BUILD_HASH}`;

// Núcleo para arrancar sin red. Con la app construida, todo lo publicado; sin construir,
// lo mínimo (los módulos ES se cachean sobre la marcha).
const SHELL = PRECACHE.length
    ? ['./', ...PRECACHE]
    : ['./', './index.html', './css/style.css', './css/fonts/outfit-latin.woff2', './css/fonts/jetbrains-mono-latin.woff2', './manifest.webmanifest', './icon.svg'];

// Nombre con el hash de contenido que pone esbuild (8 caracteres en mayúsculas y cifras).
const HASHED = /-[A-Z0-9]{8}\.(?:js|css)$/;

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE)
            // addAll es atómico: si un recurso falla, no se instala nada. Se piden de
            // uno en uno para que un 404 puntual no deje la app sin caché.
            .then(cache => Promise.all(SHELL.map(url => cache.add(url).catch(() => null))))
            .then(() => self.skipWaiting())
    );
});

// Secuencia de una caché nuestra ('esc-shell-1729…-v5.2.0-3KX7Q2LM' → 1729…), o -1 si es
// de un formato anterior.
const seqOf = (name) => {
    const m = name.slice(CACHE_PREFIX.length).match(/^(\d+)-/);
    return m ? Number(m[1]) : -1;
};

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => {
                const ours = keys.filter(k => k.startsWith(CACHE_PREFIX) && k !== CACHE);
                // Se conserva la generación ANTERIOR: una pestaña que siga abierta con la
                // versión de antes aún puede pedir sus trozos diferidos (el idioma, el
                // informe), y el servidor ya no los tiene.
                const previous = ours
                    .filter(k => seqOf(k) >= 0 && seqOf(k) < BUILD_SEQ)
                    .sort((a, b) => seqOf(b) - seqOf(a))[0];
                return Promise.all(ours.filter(k => k !== previous).map(k => caches.delete(k)));
            })
            .then(() => self.clients.claim())
    );
});

// Red primero; si la respuesta es buena se guarda, y sin red, lo guardado.
function networkFirst(request, cacheKey = request) {
    return fetch(request)
        .then((res) => {
            // Solo una respuesta correcta sustituye a la de la caché: un 404 o un 5xx
            // puntual del hosting dejaba la app rota también sin conexión.
            if (res && res.ok) {
                const copy = res.clone();
                caches.open(CACHE).then(c => c.put(cacheKey, copy));
            }
            return res;
        })
        .catch(() => caches.match(cacheKey).then(r => r || Response.error()));
}

self.addEventListener('fetch', (event) => {
    const { request } = event;
    if (request.method !== 'GET') return;

    const url = new URL(request.url);
    // Todo lo que no sea del propio origen (DoH, crt.sh, política MTA-STS, proxy)
    // se deja pasar sin tocar: son datos de seguridad que deben ser frescos.
    if (url.origin !== self.location.origin) return;

    // Navegación: red primero para recoger despliegues nuevos, saltándose la caché HTTP
    // (GitHub Pages sirve el HTML con max-age=600); si no hay red, el index cacheado.
    if (request.mode === 'navigate') {
        event.respondWith(networkFirst(new Request(request.url, { cache: 'no-cache', credentials: 'same-origin' }), './index.html'));
        return;
    }

    // Con hash en el nombre: inmutable. De la caché (de cualquier generación) y, si no
    // está, de la red.
    if (HASHED.test(url.pathname)) {
        event.respondWith(
            caches.match(request).then(cached => cached || fetch(request).then((res) => {
                if (res && res.ok) {
                    const copy = res.clone();
                    caches.open(CACHE).then(c => c.put(request, copy));
                }
                return res;
            }))
        );
        return;
    }

    // Sin hash (la app sin construir), el HTML, el CSS y los módulos ES están ACOPLADOS
    // entre sí por versión: con stale-while-revalidate, tras un cambio una misma carga
    // podía mezclar módulos viejos y nuevos. Van a red primero.
    if (/\.(?:js|css|html)$/.test(url.pathname)) {
        event.respondWith(networkFirst(request));
        return;
    }

    // El resto (fuentes, iconos, manifest) no depende de la versión del código:
    // se sirve de caché al instante y se refresca en segundo plano.
    event.respondWith(
        caches.match(request).then(cached => {
            const network = fetch(request)
                .then(res => {
                    if (res && res.ok) {
                        const copy = res.clone();
                        caches.open(CACHE).then(c => c.put(request, copy));
                    }
                    return res;
                })
                .catch(() => cached);
            return cached || network;
        })
    );
});

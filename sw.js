/**
 * Service worker: cachea el "app shell" para que la herramienta abra al instante y
 * siga siendo utilizable sin conexión (la interfaz, el visor de informes DMARC y el
 * analizador de cabeceras funcionan enteros en local; el análisis DNS, obviamente, no).
 *
 * Regla de oro: NADA de tráfico externo se cachea. Las consultas DoH, los CT logs y
 * la política MTA-STS van siempre a la red — un análisis servido desde caché daría
 * un diagnóstico de seguridad desactualizado, que es peor que no dar ninguno.
 */
// Generación de la caché, no la versión de la app: se sube cada vez que cambia el
// app shell para que los clientes descarten lo viejo.
const SW_VERSION = 'v3.1.1';
const CACHE = `esc-shell-${SW_VERSION}`;

// Núcleo mínimo para arrancar sin red. El resto de módulos ES se cachea sobre la
// marcha (stale-while-revalidate), así no hay que mantener la lista a mano.
const SHELL = [
    './',
    './index.html',
    './css/style.css',
    './css/fonts/outfit-latin.woff2',
    './css/fonts/jetbrains-mono-latin.woff2',
    './manifest.webmanifest',
    './icon.svg',
    './js/bootstrap.js',
    './js/app.js',
    './js/ui.js',
    './js/api.js',
    './js/analyzer.js',
    './js/parsers.js',
    './js/i18n.js'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE)
            // addAll es atómico: si un recurso falla, no se instala nada. Se piden de
            // uno en uno para que un 404 puntual no deje la app sin caché.
            .then(cache => Promise.all(SHELL.map(url => cache.add(url).catch(() => null))))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const { request } = event;
    if (request.method !== 'GET') return;

    const url = new URL(request.url);
    // Todo lo que no sea del propio origen (DoH, crt.sh, política MTA-STS, proxy)
    // se deja pasar sin tocar: son datos de seguridad que deben ser frescos.
    if (url.origin !== self.location.origin) return;

    // Navegación: red primero para recoger despliegues nuevos; si no hay red, el
    // index cacheado.
    if (request.mode === 'navigate') {
        event.respondWith(
            fetch(request)
                .then(res => {
                    const copy = res.clone();
                    caches.open(CACHE).then(c => c.put('./index.html', copy));
                    return res;
                })
                .catch(() => caches.match('./index.html').then(r => r || Response.error()))
        );
        return;
    }

    // El HTML, el CSS y los módulos ES están ACOPLADOS entre sí por versión. Con
    // stale-while-revalidate, tras un despliegue una misma carga podía mezclar
    // módulos viejos y nuevos y romper la app (visto en pruebas: un ui.js cacheado
    // llamando a un panel ya cambiado). Para esos van a red primero, con la caché
    // como respaldo cuando no hay conexión.
    const versionCoupled = /\.(?:js|css|html)$/.test(url.pathname);
    if (versionCoupled) {
        event.respondWith(
            fetch(request)
                .then(res => {
                    if (res && res.ok) {
                        const copy = res.clone();
                        caches.open(CACHE).then(c => c.put(request, copy));
                    }
                    return res;
                })
                .catch(() => caches.match(request).then(r => r || Response.error()))
        );
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

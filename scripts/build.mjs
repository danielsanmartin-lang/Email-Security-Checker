#!/usr/bin/env node
// Construye la versión que se publica, en dist/.
//
// Uso:  node scripts/build.mjs        (o npm run build)
//
// La app funciona sin construir (módulos ES servidos tal cual: así se desarrolla y así
// corren los tests). Publicada así, el navegador descubría los ~35 módulos en cascada,
// nivel a nivel de imports, y el service worker tenía que ir a la red en cada carga para
// no mezclar versiones. Aquí:
//   · esbuild empaqueta y minifica desde js/bootstrap.js. Lo que se carga bajo demanda
//     (inglés y alemán, el informe exportable, el detector de awareness) sale en trozos
//     aparte que solo se descargan si se usan.
//   · Cada fichero lleva un hash de su contenido en el nombre: no cambia nunca, así que
//     el service worker lo sirve de caché sin preguntar.
//   · index.html se reescribe para apuntar a los ficheros con hash y precargar (con
//     modulepreload) los trozos que la entrada importa de forma estática.
//   · sw.js recibe la lista de ficheros publicados y una secuencia de generación.
// Cualquier marcador que falte hace fallar la construcción: mejor un despliegue roto
// en CI que una app rota en producción.
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const toUrlPath = (p) => p.split(sep).join('/');
const shortHash = (buf) => createHash('sha256').update(buf).digest('base64url').replace(/[^A-Za-z0-9]/g, '').slice(0, 8).toUpperCase();

/**
 * Opciones de esbuild que deciden cómo queda el código publicado. Exportadas para que el
 * test pueda empaquetar el motor de análisis EXACTAMENTE igual y comprobar que minificado
 * calcula la misma nota: renombrar funciones ya rompió una vez la puntuación.
 */
export const ESBUILD_OPTIONS = {
    bundle: true,
    format: 'esm',
    minify: true,
    target: ['es2022'],
    charset: 'utf8',
    legalComments: 'none'
};

/** Sustituye `from` por `to` exactamente una vez; si no está, la construcción falla. */
function replaceOnce(text, from, to, what) {
    const count = text.split(from).length - 1;
    if (count !== 1) throw new Error(`build: ${what}: se esperaba 1 aparición de ${JSON.stringify(from)} y hay ${count}`);
    return text.replace(from, () => to);
}

async function listFiles(dir) {
    const out = [];
    for (const entry of await readdir(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) out.push(...await listFiles(full));
        else out.push(full);
    }
    return out;
}

/**
 * @param {{ outDir?: string, logLevel?: string, seq?: number }} [opts]
 * @returns {Promise<{ outDir: string, entry: string, preload: string[], css: string, files: string[], cacheId: string }>}
 */
export async function buildSite({ outDir = join(ROOT, 'dist'), logLevel = 'warning', seq = Date.now() } = {}) {
    await rm(outDir, { recursive: true, force: true });
    await mkdir(outDir, { recursive: true });

    // --- JavaScript ---
    const result = await build({
        ...ESBUILD_OPTIONS,
        absWorkingDir: ROOT,
        entryPoints: ['js/bootstrap.js'],
        splitting: true,
        outdir: join(outDir, 'js'),
        entryNames: '[name]-[hash]',
        chunkNames: 'chunks/[name]-[hash]',
        metafile: true,
        logLevel
    });
    const outputs = result.metafile.outputs;
    const rel = (key) => toUrlPath(relative(outDir, join(ROOT, key)));
    const entryKey = Object.keys(outputs).find(k => outputs[k].entryPoint === 'js/bootstrap.js');
    if (!entryKey) throw new Error('build: esbuild no generó la entrada js/bootstrap.js');
    const entry = rel(entryKey);
    // Lo que la entrada importa de forma estática se descarga seguro: se precarga.
    const preload = outputs[entryKey].imports.filter(i => i.kind === 'import-statement').map(i => rel(i.path));

    // --- CSS (las fuentes van por ruta relativa: el CSS se queda en css/) ---
    const cssSource = await readFile(join(ROOT, 'css/style.css'));
    const css = `css/style-${shortHash(cssSource)}.css`;
    await mkdir(join(outDir, 'css'), { recursive: true });
    await writeFile(join(outDir, css), cssSource);
    await cp(join(ROOT, 'css/fonts'), join(outDir, 'css/fonts'), { recursive: true });
    for (const f of ['manifest.webmanifest', 'icon.svg']) await cp(join(ROOT, f), join(outDir, f));

    // --- index.html ---
    let html = await readFile(join(ROOT, 'index.html'), 'utf8');
    html = replaceOnce(html, '<link rel="stylesheet" href="css/style.css">', `<link rel="stylesheet" href="${css}">`, 'index.html (CSS)');
    html = replaceOnce(html, '</head>', [entry, ...preload].map(p => `    <link rel="modulepreload" href="${p}">\n`).join('') + '</head>', 'index.html (modulepreload)');
    html = replaceOnce(html, '<script type="module" src="js/bootstrap.js"></script>', `<script type="module" src="${entry}"></script>`, 'index.html (script)');
    await writeFile(join(outDir, 'index.html'), html);

    // --- sw.js: la lista de lo publicado y la generación de la caché ---
    const files = (await listFiles(outDir)).map(f => toUrlPath(relative(outDir, f))).sort();
    const cacheId = shortHash(Buffer.from(files.join('\n') + html));
    let sw = await readFile(join(ROOT, 'sw.js'), 'utf8');
    sw = replaceOnce(sw, 'const BUILD_SEQ = 0;', `const BUILD_SEQ = ${Number(seq)};`, 'sw.js (BUILD_SEQ)');
    sw = replaceOnce(sw, "const BUILD_HASH = 'dev';", `const BUILD_HASH = '${cacheId}';`, 'sw.js (BUILD_HASH)');
    sw = replaceOnce(sw, 'const PRECACHE = [];', `const PRECACHE = ${JSON.stringify(files.map(f => `./${f}`))};`, 'sw.js (PRECACHE)');
    await writeFile(join(outDir, 'sw.js'), sw);

    return { outDir, entry, preload, css, files: [...files, 'sw.js'].sort(), cacheId };
}

// Ejecutado como script (no importado por el test): construye y resume.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
    const out = await buildSite({ logLevel: 'info' });
    let total = 0;
    for (const f of out.files.filter(f => f.endsWith('.js') || f.endsWith('.css'))) {
        total += (await readFile(join(out.outDir, f))).length;
    }
    console.log(`dist/ listo: ${out.files.length} ficheros, ${(total / 1024).toFixed(0)} KB de JS y CSS. Entrada: ${out.entry}`);
}

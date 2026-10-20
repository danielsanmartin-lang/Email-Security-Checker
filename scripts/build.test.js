// La construcción decide lo que llega a producción: si apunta a un fichero que no existe,
// la app publicada no arranca y los tests de js/ (que corren sobre el código sin
// construir) no se enterarían. Este test construye en un directorio temporal y comprueba
// que todo lo que se referencia existe.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { build } from 'esbuild';
import { vi } from 'vitest';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { buildSite, ESBUILD_OPTIONS } from './build.mjs';

let out;
let tmp;
const exists = (p) => access(p).then(() => true, () => false);

beforeAll(async () => {
    tmp = await mkdtemp(join(tmpdir(), 'esc-build-'));
    out = await buildSite({ outDir: join(tmp, 'dist'), logLevel: 'silent', seq: 1234 });
}, 30000);

afterAll(() => rm(tmp, { recursive: true, force: true }));

describe('scripts/build.mjs', () => {
    it('index.html apunta a la entrada con hash, al CSS con hash y precarga lo que importa', async () => {
        const html = await readFile(join(out.outDir, 'index.html'), 'utf8');
        expect(out.entry).toMatch(/^js\/bootstrap-[A-Z0-9]{8}\.js$/);
        expect(html).toContain(`<script type="module" src="${out.entry}"></script>`);
        expect(html).not.toContain('src="js/bootstrap.js"');
        expect(html).toContain(`<link rel="stylesheet" href="${out.css}">`);
        for (const p of [out.entry, ...out.preload]) expect(html).toContain(`<link rel="modulepreload" href="${p}">`);
        const refs = [...html.matchAll(/(?:src|href)="((?:js|css)\/[^"]+)"/g)].map(m => m[1]);
        for (const ref of refs) expect(await exists(join(out.outDir, ref)), ref).toBe(true);
    });

    it('conserva la CSP del index original', async () => {
        const csp = (h) => h.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)[1];
        const source = await readFile(new URL('../index.html', import.meta.url), 'utf8');
        const built = await readFile(join(out.outDir, 'index.html'), 'utf8');
        expect(csp(built)).toBe(csp(source));
    });

    it('las fuentes que pide el CSS existen junto a él', async () => {
        const css = await readFile(join(out.outDir, out.css), 'utf8');
        const urls = [...css.matchAll(/url\(['"]?([^'")]+)['"]?\)/g)].map(m => m[1]).filter(u => !u.startsWith('data:'));
        expect(urls.length).toBeGreaterThan(0);
        for (const u of urls) expect(await exists(join(out.outDir, dirname(out.css), u)), u).toBe(true);
    });

    it('el service worker precarga exactamente lo publicado, con su generación', async () => {
        const sw = await readFile(join(out.outDir, 'sw.js'), 'utf8');
        const precache = JSON.parse(sw.match(/const PRECACHE = (\[.*?\]);/)[1]);
        expect(precache.sort()).toEqual(out.files.filter(f => f !== 'sw.js').map(f => `./${f}`).sort());
        for (const f of precache) expect(await exists(join(out.outDir, f))).toBe(true);
        expect(sw).toContain('const BUILD_SEQ = 1234;');
        expect(sw).toContain(`const BUILD_HASH = '${out.cacheId}';`);
        expect(sw).not.toContain("const BUILD_HASH = 'dev';");
    });

    it('los idiomas, el informe y el detector de awareness van en trozos aparte', () => {
        const chunks = out.files.filter(f => f.startsWith('js/chunks/'));
        for (const name of ['en', 'de', 'export', 'awarenessDetector']) {
            expect(chunks.some(f => new RegExp(`/${name}-[A-Z0-9]{8}\\.js$`).test(f)), name).toBe(true);
            expect(out.preload.some(p => p.includes(`/${name}-`)), `${name} no se precarga`).toBe(false);
        }
    });

    it('no publica tests ni código sin construir', () => {
        expect(out.files.some(f => f.endsWith('.test.js'))).toBe(false);
        expect(out.files).not.toContain('js/bootstrap.js');
        expect(out.files).not.toContain('js/api.js');
    });
});

describe('el motor de análisis, minificado, calcula lo mismo que sin construir', () => {
    // DoH simulado: un dominio con gateway en el MX, DMARC en reject y DKIM, para que
    // los tres ejes de la nota puntúen.
    const TXT = (v) => ({ Status: 0, Answer: [{ type: 16, data: `"${v}"` }] });
    const answer = (name, type) => {
        if (name === 'acme.com' && type === 'NS') return { Status: 0, Answer: [{ type: 2, data: 'ns1.acme.com.' }] };
        if (name === 'acme.com' && type === 'MX') return { Status: 0, Answer: [{ type: 15, data: '10 mxa-0001.gslb.pphosted.com.' }] };
        if (name === 'acme.com' && type === 'TXT') return TXT('v=spf1 include:_spf.google.com -all');
        if (name === '_spf.google.com' && type === 'TXT') return TXT('v=spf1 ip4:1.2.3.0/24 -all');
        if (name === '_dmarc.acme.com' && type === 'TXT') return TXT('v=DMARC1; p=reject; rua=mailto:d@acme.com');
        if (name === '_mta-sts.acme.com' && type === 'TXT') return TXT('v=STSv1; id=1');
        if (name === 'acme.com' && type === 'DNSKEY') return { Status: 0, AD: true, Answer: [{ type: 48, data: 'k' }] };
        return { Status: 0 };
    };
    const summary = (card) => ({
        score: card.score,
        grade: card.grade,
        breakdown: card.breakdown.map(c => [c.id, c.score, c.counted]),
        findings: card.findings.map(f => f.key)
    });

    it('misma nota, mismo desglose y mismos hallazgos', async () => {
        const outfile = join(tmp, 'analysis-min.mjs');
        await build({ ...ESBUILD_OPTIONS, absWorkingDir: join(dirname(fileURLToPath(import.meta.url)), '..'), entryPoints: ['js/analysis.js'], outfile, platform: 'neutral', logLevel: 'silent' });
        const fetchMock = vi.fn(async (url) => {
            const u = new URL(String(url));
            return { ok: true, status: 200, json: async () => answer(u.searchParams.get('name'), u.searchParams.get('type')) };
        });
        const original = global.fetch;
        global.fetch = fetchMock;
        try {
            const built = await import(pathToFileURL(outfile).href);
            const source = await import('../js/analysis.js');
            const a = await source.performAnalysis('acme.com', null, { background: false });
            const b = await built.performAnalysis('acme.com', null, { background: false });
            expect(a.result.scoreCard.score).toBeGreaterThan(0);
            expect(summary(b.result.scoreCard)).toEqual(summary(a.result.scoreCard));
        } finally {
            global.fetch = original;
        }
    }, 30000);
});

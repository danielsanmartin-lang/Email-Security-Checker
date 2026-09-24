#!/usr/bin/env node
// Calibración de las letras de la nota contra dominios reales.
//
// Uso:  node scripts/calibrate.mjs <fichero-de-dominios> [salida.json]
//
// El fichero lleva un dominio por línea (se ignoran las vacías y las que empiezan por #).
// Cada dominio pasa por el MISMO análisis que la interfaz (js/analysis.js), sin las
// detecciones en segundo plano, y se imprime su nota, sus tres ejes y la distribución de
// la muestra. Con esa distribución se fijan los cortes de GRADE_BANDS en js/analyzer.js.
//
// Solo hace consultas DNS por DoH, igual que la herramienta: no contacta con los
// dominios medidos. Necesita Node 22 (fetch global).
import { readFile, writeFile } from 'node:fs/promises';
import { performAnalysis } from '../js/analysis.js';
import { GRADE_BANDS } from '../js/analyzer.js';

const [, , listPath, outPath] = process.argv;
if (!listPath) {
    console.error('Uso: node scripts/calibrate.mjs <fichero-de-dominios> [salida.json]');
    process.exit(1);
}

const domains = (await readFile(listPath, 'utf8'))
    .split('\n')
    .map(l => l.trim().toLowerCase())
    .filter(l => l && !l.startsWith('#'));

// Los avisos de la capa DNS (un resolver que falla y se cambia al siguiente) no son el
// resultado: se silencian para que la tabla se lea.
console.warn = () => {};

const CONCURRENCY = 2;
const rows = [];
const failed = [];
let next = 0;

async function worker() {
    while (next < domains.length) {
        const domain = domains[next++];
        try {
            const { result } = await performAnalysis(domain, null, { background: false });
            const c = result.scoreCard;
            rows.push({
                domain,
                score: c.score,
                grade: c.grade,
                cap: c.cap ? c.cap.key : null,
                antispoof: c.antispoof.score,
                filtering: c.filtering.state,
                filteringScore: c.filtering.score,
                vendors: c.filtering.vendors.join(', '),
                transport: c.transport.applicable ? c.transport.score : null
            });
            process.stderr.write('.');
        } catch (err) {
            failed.push({ domain, error: err.code || err.message });
            process.stderr.write('x');
        }
    }
}

await Promise.all(Array.from({ length: CONCURRENCY }, worker));
process.stderr.write('\n');

rows.sort((a, b) => b.score - a.score);
const pad = (v, n) => String(v ?? '—').padEnd(n);
console.log(`${pad('dominio', 28)}${pad('nota', 6)}${pad('letra', 6)}${pad('supl.', 6)}${pad('filtrado', 26)}${pad('transp.', 8)}tope`);
for (const r of rows) {
    const filt = `${r.filtering}${r.vendors ? ` (${r.vendors})` : ''}`;
    console.log(`${pad(r.domain, 28)}${pad(r.score, 6)}${pad(r.grade, 6)}${pad(r.antispoof, 6)}${pad(filt.slice(0, 25), 26)}${pad(r.transport, 8)}${r.cap || ''}`);
}

// Percentiles "desde arriba": el valor que deja por encima a ese porcentaje de la muestra.
const scores = rows.map(r => r.score);
const topShare = (pct) => scores[Math.min(scores.length - 1, Math.max(0, Math.ceil((pct / 100) * scores.length) - 1))];
console.log(`\nMuestra: ${rows.length} dominios (${failed.length} sin resolver)`);
for (const pct of [5, 10, 25, 50, 60, 75, 90]) console.log(`  el ${pct} % mejor saca ${topShare(pct)} o más`);
const byGrade = {};
for (const b of GRADE_BANDS) byGrade[b.grade] = rows.filter(r => r.grade === b.grade).length;
console.log('Reparto con los cortes actuales:', byGrade);
const byFilter = {};
for (const r of rows) byFilter[r.filtering] = (byFilter[r.filtering] || 0) + 1;
console.log('Filtrado:', byFilter);
if (failed.length) console.log('Sin resolver:', failed.map(f => `${f.domain} (${f.error})`).join(', '));

if (outPath) await writeFile(outPath, JSON.stringify({ date: new Date().toISOString(), rows, failed }, null, 2));

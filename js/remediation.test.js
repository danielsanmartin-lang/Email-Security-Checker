import { describe, it, expect } from 'vitest';
import { buildRemediation, splitTxt } from './remediation.js';
import { evaluateDmarc } from './dmarc.js';
import { parseDMARC, parseSPF } from './parsers.js';

const NOW = Date.parse('2026-10-19T12:00:00Z');
const MX = [{ priority: 10, host: 'mx1.acme.com' }, { priority: 20, host: 'mx2.acme.com' }];

// Un result mínimo: lo que buildRemediation lee, con DMARC evaluado como lo hace analyze().
function result({ dmarc = 'v=DMARC1; p=reject; rua=mailto:r@acme.com', spf = 'v=spf1 include:_spf.google.com -all', mx = MX, ...rest } = {}) {
    return {
        mxRecords: mx,
        nullMx: false,
        dmarcEval: dmarc ? evaluateDmarc(parseDMARC(dmarc)) : null,
        spfRaw: spf,
        spfData: { record: spf, records: spf ? [spf] : [], multiple: false },
        spfLookups: 1,
        spfTree: null,
        mtaSts: { record: 'v=STSv1; id=1', policy: { validationReason: 'not_fetched' } },
        tlsRpt: { record: 'v=TLSRPTv1; rua=mailto:t@acme.com', rua: ['mailto:t@acme.com'] },
        dmarcExternalAuth: [],
        ...rest
    };
}
const ids = (list) => list.map(r => r.id);
const keys = (r) => r.notes.map(n => n.key);

describe('buildRemediation: un dominio bien configurado', () => {
    it('no propone nada', () => {
        expect(buildRemediation(result(), 'acme.com', { now: NOW })).toEqual([]);
    });
});

describe('buildRemediation: DMARC', () => {
    it('sin DMARC: la escalera entera, con un buzón de ejemplo avisado una vez', () => {
        const list = buildRemediation(result({ dmarc: null }), 'acme.com', { now: NOW });
        const dmarc = list.filter(r => r.id.startsWith('dmarc_'));
        expect(ids(dmarc)).toEqual(['dmarc_monitor', 'dmarc_quarantine', 'dmarc_reject']);
        expect(dmarc.map(r => r.host)).toEqual(['_dmarc.acme.com', '_dmarc.acme.com', '_dmarc.acme.com']);
        expect(dmarc[0].value).toBe('v=DMARC1; p=none; rua=mailto:dmarc-reports@acme.com');
        expect(dmarc[2].value).toBe('v=DMARC1; p=reject; rua=mailto:dmarc-reports@acme.com');
        expect(keys(dmarc[0])).toContain('rem_example_mailbox');
        expect(dmarc.slice(1).some(r => keys(r).includes('rem_example_mailbox'))).toBe(false);
    });

    it('con p=none conserva sus destinos de informe y sus alineaciones estrictas', () => {
        const list = buildRemediation(result({ dmarc: 'v=DMARC1; p=none; rua=mailto:a@acme.com,mailto:b@x.com; adkim=s' }), 'acme.com', { now: NOW });
        const reject = list.find(r => r.id === 'dmarc_reject');
        expect(reject.value).toBe('v=DMARC1; p=reject; rua=mailto:a@acme.com,mailto:b@x.com; adkim=s');
        expect(list.some(r => keys(r).includes('rem_example_mailbox'))).toBe(false);
    });

    it('con quarantine al 100 % solo falta el rechazo, y conserva ruf y su fo', () => {
        const dmarc = 'v=DMARC1; p=quarantine; fo=1; rua=mailto:r@acme.com; ruf=mailto:f@acme.com';
        const list = buildRemediation(result({ dmarc, dmarcParsed: parseDMARC(dmarc) }), 'acme.com', { now: NOW });
        expect(ids(list)).toEqual(['dmarc_reject']);
        expect(list[0].value).toBe('v=DMARC1; p=reject; rua=mailto:r@acme.com; ruf=mailto:f@acme.com; fo=1');
    });

    it('con quarantine al 50 % repite la cuarentena sin pct antes del rechazo', () => {
        const list = buildRemediation(result({ dmarc: 'v=DMARC1; p=quarantine; pct=50; rua=mailto:r@acme.com' }), 'acme.com', { now: NOW });
        expect(ids(list)).toEqual(['dmarc_quarantine', 'dmarc_reject']);
        expect(list[0].value).not.toContain('pct');
    });

    it('con reject pero sp=none, corrige la política de los subdominios', () => {
        const list = buildRemediation(result({ dmarc: 'v=DMARC1; p=reject; sp=none; rua=mailto:r@acme.com' }), 'acme.com', { now: NOW });
        expect(ids(list)).toEqual(['dmarc_reject']);
        expect(keys(list[0])).toEqual(['rem_dmarc_subdomains']);
        expect(list[0].value).not.toContain('sp=');
    });

    it('pide al destino externo no autorizado el registro que le falta', () => {
        const list = buildRemediation(result({
            dmarcPolicyDomain: 'acme.com',
            dmarcExternalAuth: [
                { uri: 'mailto:x@vendor.com', destDomain: 'vendor.com', authorized: false },
                { uri: 'mailto:y@ok.com', destDomain: 'ok.com', authorized: true },
                { uri: 'mailto:z@nose.com', destDomain: 'nose.com', authorized: null }
            ]
        }), 'acme.com', { now: NOW });
        expect(list).toEqual([{
            id: 'dmarc_external_vendor.com',
            host: 'acme.com._report._dmarc.vendor.com',
            type: 'TXT',
            value: 'v=DMARC1',
            notes: [{ key: 'rem_dmarc_external', vars: { dest: 'vendor.com', domain: 'acme.com' } }]
        }]);
    });
});

describe('buildRemediation: SPF', () => {
    it('sin SPF y sin correo: declara que no envía', () => {
        const list = buildRemediation(result({ spf: null, mx: [] }), 'parked.com', { now: NOW });
        const spf = list.find(r => r.id === 'spf_none');
        expect(spf.value).toBe('v=spf1 -all');
        expect(keys(spf)).toEqual(['rem_spf_none_nomail']);
    });

    it('sin SPF y con buzones en Microsoft 365: plantilla con su include', () => {
        const list = buildRemediation(result({ spf: null, mailHosting: { platform: 'm365' } }), 'acme.com', { now: NOW });
        expect(list.find(r => r.id === 'spf_none').value).toBe('v=spf1 include:spf.protection.outlook.com ~all');
    });

    it('cierra un +all (o la falta de all) con ~all', () => {
        for (const spf of ['v=spf1 include:_spf.google.com +all', 'v=spf1 include:_spf.google.com', 'v=spf1 mx ?all']) {
            const fix = buildRemediation(result({ spf }), 'acme.com', { now: NOW }).find(r => r.id === 'spf_fix');
            expect(fix.value.endsWith(' ~all')).toBe(true);
            expect(fix.value.match(/all/g)).toHaveLength(1);
            expect(keys(fix)).toContain('rem_spf_all');
        }
    });

    it('fusiona varios registros en uno, con el all más estricto', () => {
        const a = 'v=spf1 include:_spf.google.com ~all';
        const b = 'v=spf1 include:spf.protection.outlook.com include:_spf.google.com -all';
        const fix = buildRemediation(result({ spf: a, spfData: { record: a, records: [a, b], multiple: true } }), 'acme.com', { now: NOW })
            .find(r => r.id === 'spf_fix');
        expect(fix.value).toBe('v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all');
        expect(keys(fix)).toEqual(['rem_spf_merge']);
    });

    it('quita los include cuyo destino no publica SPF', () => {
        const spf = 'v=spf1 include:roto.example include:_spf.google.com -all';
        const spfTree = {
            domain: 'acme.com', lookups: 2, record: spf,
            children: [
                { type: 'include', target: 'roto.example', tree: { error: 'no_spf_record', lookups: 0, children: [] } },
                { type: 'include', target: '_spf.google.com', tree: { record: 'v=spf1 ip4:1.2.3.0/24 -all', lookups: 0, children: [] } }
            ]
        };
        const fix = buildRemediation(result({ spf, spfTree }), 'acme.com', { now: NOW }).find(r => r.id === 'spf_fix');
        expect(fix.value).toBe('v=spf1 include:_spf.google.com -all');
        expect(fix.notes).toEqual([{ key: 'rem_spf_broken', vars: { targets: 'roto.example' } }]);
    });

    it('con más de 10 consultas aplana los include más caros que solo tienen IPs', () => {
        // pesado.example: 1 + 9 consultas, todas includes de solo IPs; mx:… no se puede aplanar.
        const leaf = (i) => ({ type: 'include', target: `h${i}.example`, tree: { record: `v=spf1 ip4:10.0.${i}.0/24 -all`, lookups: 0, children: [] } });
        const heavy = { record: `v=spf1 ${Array.from({ length: 9 }, (_, i) => `include:h${i}.example`).join(' ')} -all`, lookups: 9, children: Array.from({ length: 9 }, (_, i) => leaf(i)) };
        const spf = 'v=spf1 include:pesado.example include:conmx.example -all';
        const spfTree = {
            domain: 'acme.com', lookups: 12, record: spf,
            children: [
                { type: 'include', target: 'pesado.example', tree: heavy },
                { type: 'include', target: 'conmx.example', tree: { record: 'v=spf1 mx -all', lookups: 1, children: [] } }
            ]
        };
        const fix = buildRemediation(result({ spf, spfTree, spfLookups: 12 }), 'acme.com', { now: NOW }).find(r => r.id === 'spf_fix');
        expect(fix.value).toContain('ip4:10.0.0.0/24');
        expect(fix.value).toContain('ip4:10.0.8.0/24');
        expect(fix.value).not.toContain('pesado.example');
        expect(fix.value).toContain('include:conmx.example');
        expect(fix.notes[0]).toEqual({ key: 'rem_spf_flatten', vars: { lookups: 12, targets: 'pesado.example' } });
        // Sigue siendo un SPF que el parser entiende.
        expect(parseSPF(fix.value).filter(e => e.type === 'ip4')).toHaveLength(9);
    });

    it('avisa si ni aplanando baja de 10', () => {
        const spf = 'v=spf1 include:a.example -all';
        const spfTree = { domain: 'acme.com', lookups: 14, record: spf, children: [{ type: 'include', target: 'a.example', tree: { record: 'v=spf1 a mx -all', lookups: 13, children: [] } }] };
        const fix = buildRemediation(result({ spf, spfTree, spfLookups: 14 }), 'acme.com', { now: NOW }).find(r => r.id === 'spf_fix');
        expect(keys(fix)).toEqual(['rem_spf_flatten_partial']);
    });
});

describe('splitTxt', () => {
    it('deja igual lo que cabe en una cadena', () => {
        expect(splitTxt('v=spf1 -all')).toEqual({ value: 'v=spf1 -all', split: false });
    });

    it('parte por mecanismos en cadenas de 255 como mucho', () => {
        const long = `v=spf1 ${Array.from({ length: 40 }, (_, i) => `ip4:192.168.${i}.0/24`).join(' ')} -all`;
        const { value, split } = splitTxt(long);
        expect(split).toBe(true);
        const chunks = [...value.matchAll(/"([^"]*)"/g)].map(m => m[1]);
        expect(chunks.length).toBeGreaterThan(1);
        expect(chunks.every(c => c.length <= 255)).toBe(true);
        expect(chunks.join('')).toBe(long);
    });
});

describe('buildRemediation: MTA-STS y TLS-RPT', () => {
    it('sin MTA-STS: el TXT con id de fecha y la política en testing con los MX reales', () => {
        const list = buildRemediation(result({ mtaSts: null }), 'acme.com', { now: NOW });
        const txt = list.find(r => r.id === 'mtasts_txt');
        const file = list.find(r => r.id === 'mtasts_file');
        expect(txt).toMatchObject({ host: '_mta-sts.acme.com', value: 'v=STSv1; id=2026101901' });
        expect(file.host).toBe('https://mta-sts.acme.com/.well-known/mta-sts.txt');
        expect(file.type).toBe('HTTPS');
        expect(file.value).toBe('version: STSv1\nmode: testing\nmx: mx1.acme.com\nmx: mx2.acme.com\nmax_age: 604800');
    });

    it('una política en testing que funciona: la versión en enforce', () => {
        const mtaSts = { record: 'v=STSv1; id=1', policy: { fetchOk: true, parsed: { mode: 'testing', mx: ['*.acme.com'], max_age: '604800' } } };
        const file = buildRemediation(result({ mtaSts }), 'acme.com', { now: NOW }).find(r => r.id === 'mtasts_file');
        expect(file.value).toContain('mode: enforce');
        expect(keys(file)).toEqual(['rem_mtasts_enforce']);
    });

    it('una política que no cubre un MX real o con max_age bajo: versión corregida', () => {
        const mtaSts = { record: 'v=STSv1; id=1', policy: { fetchOk: true, parsed: { mode: 'enforce', mx: ['mx1.acme.com'], max_age: '86400' } } };
        const file = buildRemediation(result({ mtaSts }), 'acme.com', { now: NOW }).find(r => r.id === 'mtasts_file');
        expect(file.value).toContain('mode: enforce');
        expect(file.value).toContain('mx: mx2.acme.com');
        expect(keys(file)).toEqual(['rem_mtasts_fix']);
    });

    it('sin la política descargada no se inventa nada; si su host no existe, se propone', () => {
        expect(buildRemediation(result(), 'acme.com', { now: NOW }).some(r => r.id.startsWith('mtasts'))).toBe(false);
        const missing = { record: 'v=STSv1; id=1', policy: { validationReason: 'host_missing' } };
        expect(ids(buildRemediation(result({ mtaSts: missing }), 'acme.com', { now: NOW }))).toEqual(['mtasts_file']);
    });

    it('sin TLS-RPT: el registro, con el buzón marcado como ejemplo', () => {
        const tls = buildRemediation(result({ tlsRpt: null }), 'acme.com', { now: NOW }).find(r => r.id === 'tlsrpt');
        expect(tls).toMatchObject({ host: '_smtp._tls.acme.com', value: 'v=TLSRPTv1; rua=mailto:tls-reports@acme.com' });
        expect(keys(tls)).toEqual(['rem_tlsrpt', 'rem_example_mailbox']);
    });

    it('un dominio que no recibe correo no necesita ni MTA-STS ni TLS-RPT', () => {
        const list = buildRemediation(result({ mx: [], mtaSts: null, tlsRpt: null }), 'acme.com', { now: NOW });
        expect(list.some(r => r.id.startsWith('mtasts') || r.id === 'tlsrpt')).toBe(false);
    });
});

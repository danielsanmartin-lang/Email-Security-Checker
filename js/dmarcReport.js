/**
 * dmarcReport.js
 * Visor de informes agregados DMARC (RUA). Es el paso siguiente natural a "tienes
 * rua configurado": el análisis DNS dice qué política publicas, y el informe dice
 * QUIÉN está enviando en tu nombre y si esos envíos pasan la autenticación. Sin
 * esos datos, endurecer la política a p=reject es un salto a ciegas.
 *
 * 100% LOCAL: descomprime y parsea en el navegador. El fichero no se sube a ningún
 * sitio y no se hace ninguna consulta de red (tampoco PTR sobre las IPs de origen),
 * porque un informe DMARC contiene el mapa de remitentes de una organización.
 *
 * Formatos: .xml, .xml.gz (DecompressionStream) y .zip (lector mínimo del directorio
 * central + deflate-raw). Los tres son los que emiten Google, Microsoft y Yahoo.
 */

const ZIP_EOCD_SIG = 0x06054b50;
const ZIP_CENTRAL_SIG = 0x02014b50;
const ZIP_LOCAL_SIG = 0x04034b50;

/** ¿Soporta este navegador la descompresión nativa? Si no, solo se admite .xml. */
export function supportsDecompression() {
    return typeof DecompressionStream !== 'undefined';
}

// Se alimenta el DecompressionStream a mano en vez de pasar por Blob.stream():
// así funciona igual en el navegador y en jsdom (que no implementa Blob.stream).
async function inflate(bytes, format) {
    const ds = new DecompressionStream(format);
    const writer = ds.writable.getWriter();
    writer.write(bytes);
    writer.close();
    const reader = ds.readable.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.length;
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

/**
 * Extrae el primer fichero de un ZIP (los informes DMARC traen uno solo).
 * Se lee el directorio central en vez de asumir el orden de los locales: es lo que
 * hace un descompresor real y evita fallar con ficheros con data descriptor.
 */
async function unzipFirstEntry(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // El EOCD está al final, pero puede llevar comentario detrás: se busca hacia atrás.
    let eocd = -1;
    for (let i = bytes.length - 22; i >= 0 && i > bytes.length - 22 - 65535; i--) {
        if (view.getUint32(i, true) === ZIP_EOCD_SIG) { eocd = i; break; }
    }
    if (eocd === -1) throw new Error('ZIP inválido: no se encontró el directorio central');
    const entries = view.getUint16(eocd + 10, true);
    if (entries === 0) throw new Error('El ZIP está vacío');
    const offset = view.getUint32(eocd + 16, true);

    if (view.getUint32(offset, true) !== ZIP_CENTRAL_SIG) throw new Error('ZIP inválido: directorio central corrupto');
    const method = view.getUint16(offset + 10, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const nameLen = view.getUint16(offset + 28, true);
    const extraLen = view.getUint16(offset + 30, true);
    const commentLen = view.getUint16(offset + 32, true);
    const localOffset = view.getUint32(offset + 42, true);
    void nameLen; void extraLen; void commentLen;

    if (view.getUint32(localOffset, true) !== ZIP_LOCAL_SIG) throw new Error('ZIP inválido: cabecera local corrupta');
    const localNameLen = view.getUint16(localOffset + 26, true);
    const localExtraLen = view.getUint16(localOffset + 28, true);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const data = bytes.subarray(dataStart, dataStart + compressedSize);

    if (method === 0) return data;               // almacenado sin comprimir
    if (method === 8) return inflate(data, 'deflate-raw');
    throw new Error(`Método de compresión ZIP no soportado (${method})`);
}

/**
 * Convierte un File/Blob en el texto XML del informe, descomprimiendo si hace falta.
 * @param {File} file
 * @returns {Promise<string>}
 */
export async function extractReportXml(file) {
    const name = (file.name || '').toLowerCase();
    const bytes = new Uint8Array(await file.arrayBuffer());

    // Se detecta por número mágico y no solo por extensión: muchos informes llegan
    // con el nombre cambiado al reenviarlos por correo.
    const isGzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
    const isZip = bytes[0] === 0x50 && bytes[1] === 0x4b;

    if (isGzip || isZip) {
        if (!supportsDecompression()) {
            throw new Error('unsupported_compression');
        }
        const raw = isZip ? await unzipFirstEntry(bytes) : await inflate(bytes, 'gzip');
        return new TextDecoder().decode(raw);
    }
    if (name.endsWith('.gz') || name.endsWith('.zip')) {
        throw new Error('El fichero dice estar comprimido pero no lo está');
    }
    return new TextDecoder().decode(bytes);
}

const text = (node, tag) => {
    const el = node?.querySelector(tag);
    return el ? el.textContent.trim() : '';
};

/**
 * Parsea y agrega un informe agregado DMARC (RFC 7489 apéndice C).
 * @param {string} xml
 * @returns {{ org, reportId, dateRange, policy, totals, sources, headerFroms }}
 */
export function parseAggregateReport(xml) {
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    if (doc.querySelector('parsererror')) throw new Error('El XML del informe no es válido');
    const feedback = doc.querySelector('feedback');
    if (!feedback) throw new Error('No parece un informe agregado DMARC (falta <feedback>)');

    const meta = feedback.querySelector('report_metadata');
    const published = feedback.querySelector('policy_published');
    const toDate = (secs) => {
        const n = parseInt(secs, 10);
        return Number.isFinite(n) ? new Date(n * 1000).toISOString() : null;
    };

    const totals = { messages: 0, dmarcPass: 0, spfPass: 0, dkimPass: 0, quarantined: 0, rejected: 0 };
    const bySource = new Map();
    const byHeaderFrom = new Map();

    for (const record of feedback.querySelectorAll('record')) {
        const row = record.querySelector('row');
        const count = parseInt(text(row, 'count'), 10) || 0;
        const evaluated = row?.querySelector('policy_evaluated');
        const dkim = text(evaluated, 'dkim').toLowerCase();
        const spf = text(evaluated, 'spf').toLowerCase();
        const disposition = (text(evaluated, 'disposition') || 'none').toLowerCase();
        // DMARC pasa si SPF o DKIM pasan **alineados**; policy_evaluated ya refleja
        // la alineación, así que es la fuente correcta (no auth_results).
        const dmarcPass = dkim === 'pass' || spf === 'pass';
        const ip = text(row, 'source_ip') || '—';
        const headerFrom = text(record.querySelector('identifiers'), 'header_from') || '—';

        totals.messages += count;
        if (dmarcPass) totals.dmarcPass += count;
        if (spf === 'pass') totals.spfPass += count;
        if (dkim === 'pass') totals.dkimPass += count;
        if (disposition === 'quarantine') totals.quarantined += count;
        if (disposition === 'reject') totals.rejected += count;

        if (!bySource.has(ip)) {
            bySource.set(ip, {
                ip, messages: 0, dmarcPass: 0, spfPass: 0, dkimPass: 0,
                dispositions: new Set(), dkimDomains: new Set(), spfDomains: new Set()
            });
        }
        const src = bySource.get(ip);
        src.messages += count;
        if (dmarcPass) src.dmarcPass += count;
        if (spf === 'pass') src.spfPass += count;
        if (dkim === 'pass') src.dkimPass += count;
        src.dispositions.add(disposition);
        for (const d of record.querySelectorAll('auth_results > dkim > domain')) src.dkimDomains.add(d.textContent.trim());
        for (const d of record.querySelectorAll('auth_results > spf > domain')) src.spfDomains.add(d.textContent.trim());

        byHeaderFrom.set(headerFrom, (byHeaderFrom.get(headerFrom) || 0) + count);
    }

    const sources = [...bySource.values()]
        .map(s => ({
            ...s,
            dispositions: [...s.dispositions],
            dkimDomains: [...s.dkimDomains],
            spfDomains: [...s.spfDomains],
            passRate: s.messages > 0 ? s.dmarcPass / s.messages : 0
        }))
        .sort((a, b) => b.messages - a.messages);

    return {
        org: text(meta, 'org_name') || '—',
        email: text(meta, 'email'),
        reportId: text(meta, 'report_id'),
        dateRange: {
            begin: toDate(text(meta?.querySelector('date_range'), 'begin')),
            end: toDate(text(meta?.querySelector('date_range'), 'end'))
        },
        policy: {
            domain: text(published, 'domain'),
            p: text(published, 'p'),
            sp: text(published, 'sp'),
            pct: text(published, 'pct'),
            adkim: text(published, 'adkim'),
            aspf: text(published, 'aspf')
        },
        totals: {
            ...totals,
            passRate: totals.messages > 0 ? totals.dmarcPass / totals.messages : 0
        },
        sources,
        headerFroms: [...byHeaderFrom.entries()]
            .map(([domain, messages]) => ({ domain, messages }))
            .sort((a, b) => b.messages - a.messages)
    };
}

/** Atajo: fichero → informe agregado ya parseado. */
export async function readReportFile(file) {
    return parseAggregateReport(await extractReportXml(file));
}

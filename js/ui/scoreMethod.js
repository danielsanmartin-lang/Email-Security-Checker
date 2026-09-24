// ui/scoreMethod.js
// Apartado "¿Cómo se calcula la nota?": qué mide la nota, la cuenta de este dominio, los
// puntos de cada regla y por qué, los topes, qué significa cada letra y lo que se informa
// sin puntuar.
//
// Los NÚMEROS salen de las constantes del motor (analyzer.js), no del texto: si cambia un
// peso, el apartado cambia con él. Los textos, de i18n. Se regenera en cada render de
// resultados, así que cambiar de idioma lo traduce aunque esté abierto.
import { html, raw } from '../utils.js';
import { translations } from '../i18n.js';
import { getLanguage, getLocale } from '../lang.js';
import {
    SCORE_CATEGORIES, CHECK_BUDGETS, SCORE_WEIGHTS as W, GRADE_BANDS, GRADE_CALIBRATION,
    NO_ENFORCEMENT_CAP, UNVERIFIED_CAP
} from '../analyzer.js';
import { scoreFormula, gradeMeaning } from '../viewmodel.js';

// Cada regla: [clave de i18n (method_rule_<id> / method_why_<id>), puntos o null si no se
// evalúa]. El orden es el de la tabla.
const RULES = {
    antispoof: [
        ['dmarc_reject', W.dmarcReject],
        ['dmarc_quarantine', W.dmarcQuarantine],
        ['dmarc_none_reports', W.dmarcNoneWithReports],
        ['dmarc_none', W.dmarcNone],
        ['dmarc_sp_none', W.dmarcSpNone],
        ['dmarc_np_none', W.dmarcNpNone],
        ['dmarc_pct', W.dmarcPctPartial],
        ['dmarc_multiple', W.dmarcMultiple],
        ['spf_pass', W.spfPass],
        ['spf_softfail', W.spfSoftfailNoDmarc],
        ['spf_neutral', W.spfNeutral],
        ['spf_ptr', W.spfPtr],
        ['dkim_strong', W.dkimStrong],
        ['dkim_1024', W.dkim1024],
        ['dkim_weak', W.dkimWeak],
        ['dkim_unknown', null],
        ['reporting', W.dmarcReporting],
        ['reporting_unauth', W.dmarcExternalUnauthorized]
    ],
    filtering: [
        ['filter_reinforced', W.filterReinforced],
        ['filter_ices_token', W.filterIcesToken],
        ['filter_bypass', W.filterBypass],
        ['filter_native', W.filterNative],
        ['filter_unidentified', W.filterUnidentified]
    ],
    transport: [
        ['mta_sts', W.mtaStsEnforce + W.mtaStsMaxAgeOk],
        ['mta_sts_unverified', W.mtaStsUnverified],
        ['mta_sts_testing', W.mtaStsTesting],
        ['tls_rpt', W.tlsRpt],
        ['dnssec', W.dnssec],
        ['dane', W.dane]
    ]
};

const UNSCORED = ['bimi', 'awareness', 'hosting', 'surface', 'lookalike', 'rbl'];

const fill = (text, values) => Object.entries(values).reduce(
    (acc, [k, v]) => acc.split(`{${k}}`).join(String(v)), text || ''
);
// Signo matemático de verdad para los negativos: el guion corto se confunde con un rango.
const points = (n, t) => (n === null ? t.score_unevaluable : n < 0 ? `−${Math.abs(n)}` : String(n));

export function buildScoreMethod(result, lang = getLanguage()) {
    const t = translations[lang];
    const card = result && result.scoreCard;
    const pct = (n) => fill(t.pct_fmt, { n });

    // 1. Qué mide y qué no
    const what = html`<h4>${t.method_what_title}</h4><p>${t.method_what_body}</p>`;

    // 2. La cuenta de este dominio
    let thisDomain = raw('');
    const f = card ? scoreFormula(t, card, getLocale(lang)) : null;
    if (f) {
        const renormalized = card.breakdown.some(c => !c.counted)
            ? html`<p>${t.method_this_renormalized}</p>` : raw('');
        thisDomain = html`<h4>${t.method_this_title}</h4>
            <p>${t.method_this_intro}</p>
            <div class="score-method__formula">${f.formula}</div>
            ${renormalized}
            ${f.cap ? html`<p>${t.method_this_cap} ${f.cap}</p>` : raw('')}
            <p><span class="score-method__grade">${f.final}</span> — ${gradeMeaning(t, card.grade)}</p>`;
    }

    // 3. Los tres ejes, regla por regla
    const axes = Object.entries(SCORE_CATEGORIES).map(([id, cat]) => {
        const budgets = Object.values(CHECK_BUDGETS)
            .filter(b => b.category === id)
            .map(b => `${t[b.labelKey] || b.labelKey} ${b.max}`)
            .join(' · ');
        const rows = RULES[id].map(([key, pts]) => html`<tr>
            <td>${t[`method_rule_${key}`]}</td>
            <td class="score-method__points">${points(pts, t)}</td>
            <td>${t[`method_why_${key}`]}</td>
        </tr>`);
        return html`<p class="score-method__axis">${t[cat.labelKey]} — ${fill(t.score_share, { share: cat.weight })}</p>
            <p>${t[`method_axis_${id}`]} <em>${budgets}</em></p>
            <table class="score-method__table">
                <thead><tr><th>${t.method_col_rule}</th><th>${t.method_col_points}</th><th>${t.method_col_why}</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>`;
    });
    const axesBlock = html`<h4>${t.method_axes_title}</h4><p>${t.method_axes_intro}</p>${axes}`;

    // 4. Topes
    const caps = html`<h4>${t.method_caps_title}</h4>
        <ul>
            <li>${fill(t.method_cap_no_enforcement, { cap: NO_ENFORCEMENT_CAP })}</li>
            <li>${fill(t.method_cap_unverified, { cap: UNVERIFIED_CAP })}</li>
        </ul>`;

    // 5. Qué significa cada letra, con su rango y su peso en la muestra de calibración
    const grades = GRADE_BANDS.map((band, i) => {
        const top = i === 0 ? 100 : GRADE_BANDS[i - 1].min - 1;
        const share = GRADE_CALIBRATION.shares[band.grade];
        return html`<li><span class="score-method__grade">${band.grade} (${band.min}–${top})</span>: ${gradeMeaning(t, band.grade)} ${typeof share === 'number' ? html`<em>${fill(t.method_grade_share, { share: pct(share) })}</em>` : raw('')}</li>`;
    });
    const gradesBlock = html`<h4>${t.method_grades_title}</h4>
        <p>${fill(t.method_grades_intro, { n: GRADE_CALIBRATION.sample })}</p>
        <ul>${grades}</ul>`;

    // 6. Lo que se informa sin puntuar
    const unscored = html`<h4>${t.method_unscored_title}</h4>
        <ul>${UNSCORED.map(k => html`<li>${t[`method_unscored_${k}`]}</li>`)}</ul>`;

    return html`${what}${thisDomain}${axesBlock}${caps}${gradesBlock}${unscored}`;
}

export function renderScoreMethod(result) {
    const body = document.getElementById('score-method-body');
    if (!body) return;
    body.innerHTML = buildScoreMethod(result);
}

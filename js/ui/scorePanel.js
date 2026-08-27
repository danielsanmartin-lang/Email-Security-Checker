// ui/scorePanel.js
// Tarjeta de puntuación: nota, grado, anillo y lista de hallazgos.
import { html, raw } from '../utils.js';
import { translations } from '../i18n.js';
import { getLanguage } from '../lang.js';
import { resolveFindingText, postureText } from '../viewmodel.js';

export function renderScorePanel(result) {
    const lang = getLanguage();
    const t = translations[lang];

    // Retrieve Security Score from result.scoreCard
    const { score, grade, cardClass, findings, posture } = result.scoreCard || { score: 0, grade: 'F', cardClass: 'danger', findings: [], posture: { grade: 'Moderada', color: 'yellow', class: 'warning', label: 'Moderada' } };

    // Render Score UI
    const scoreCard = document.getElementById('score-card');
    if (scoreCard) {
        scoreCard.className = `score-card ${cardClass}`;
        
        const titleEl = scoreCard.querySelector('.score-card__title');
        if (titleEl) {
            const postureLabel = t.posture_label;
            const postureGrade = postureText(t, posture);
            titleEl.innerHTML = html`${raw(t.score_title_panel)} <span class="tag tag--${raw(posture.class === 'safe' ? 'provider' : posture.class)}" style="margin-left: 12px; vertical-align: middle; padding: 4px 10px; font-size: 13px; border-radius: 6px; font-weight: 600;">${postureLabel}: ${postureGrade}</span>`;
        }

        const scoreNumberEl = document.getElementById('score-number');
        const scoreGradeEl = document.getElementById('score-grade');
        const ringFillEl = document.getElementById('score-ring-fill');
        const findingsEl = document.getElementById('score-findings');

        if (scoreNumberEl) scoreNumberEl.textContent = score;
        if (scoreGradeEl) scoreGradeEl.textContent = grade;
        
        if (ringFillEl) {
            const circumference = 314;
            const offset = circumference - (score / 100) * circumference;
            ringFillEl.style.strokeDashoffset = offset;
        }

        if (findingsEl) {
            findingsEl.innerHTML = html`${findings.map(f => {
                let iconColor = 'currentColor';
                let svgIcon = '';
                if (f.status === 'success') {
                    iconColor = '#10b981';
                    svgIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="20 6 9 17 5 12" />
                    </svg>`;
                } else if (f.status === 'warning') {
                    iconColor = '#f59e0b';
                    svgIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                        <line x1="12" y1="9" x2="12" y2="13" />
                        <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>`;
                } else if (f.status === 'error') {
                    iconColor = '#ef4444';
                    svgIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                    </svg>`;
                } else {
                    iconColor = '#64748b';
                    svgIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="${iconColor}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="12" y1="16" x2="12" y2="12" />
                        <line x1="12" y1="8" x2="12.01" y2="8" />
                    </svg>`;
                }
                
                const text = resolveFindingText(t, f);

                return html`<div class="finding-item">
                    <div class="finding-item__icon">${raw(svgIcon)}</div>
                    <span class="finding-item__text">${text}</span>
                </div>`;
            })}`;
        }
    }
}

/**
 * Desglose de la nota por categoría y por control. Es lo que convierte la
 * puntuación en algo defendible: se ve de dónde salen los puntos, qué control ha
 * fallado y cuál no se ha podido evaluar (que no es lo mismo que fallar).
 */
export function renderScoreBreakdown(result) {
    const body = document.getElementById('score-breakdown-body');
    if (!body) return;
    const t = translations[getLanguage()];
    const breakdown = result.scoreCard?.breakdown;
    if (!breakdown || breakdown.length === 0) {
        body.innerHTML = raw('');
        return;
    }

    const categories = breakdown.map(cat => {
        const pct = cat.max > 0 ? Math.round((cat.earned / cat.max) * 100) : 0;
        const tone = pct >= 90 ? 'good' : pct >= 50 ? 'mid' : 'bad';
        const checks = cat.checks.map(check => {
            if (check.unevaluable) {
                return html`<li class="score-check score-check--unevaluable">
                    <span class="score-check__name">${t[check.labelKey] || check.id}</span>
                    <span class="score-check__value" title="${t.score_unevaluable_hint}">${t.score_unevaluable}</span>
                </li>`;
            }
            const checkPct = check.max > 0 ? Math.round((Math.max(0, check.earned) / check.max) * 100) : 0;
            const checkTone = checkPct >= 90 ? 'good' : checkPct >= 50 ? 'mid' : 'bad';
            return html`<li class="score-check">
                <span class="score-check__name">${t[check.labelKey] || check.id}</span>
                <span class="score-check__bar"><span class="score-check__fill score-check__fill--${raw(checkTone)}" style="width:${checkPct}%"></span></span>
                <span class="score-check__value">${Math.max(0, check.earned)}/${check.max}</span>
            </li>`;
        });
        return html`<div class="score-cat">
            <div class="score-cat__head">
                <span class="score-cat__name">${t[cat.labelKey] || cat.id}</span>
                <span class="score-cat__value">${cat.earned}/${cat.max}</span>
            </div>
            <div class="score-cat__bar"><span class="score-cat__fill score-cat__fill--${raw(tone)}" style="width:${pct}%"></span></div>
            <p class="score-cat__desc">${t[`${cat.labelKey}_desc`] || ''}</p>
            <ul class="score-checks">${checks}</ul>
        </div>`;
    });

    body.innerHTML = html`<div class="score-breakdown__grid">${categories}</div>`;
}

// ui.js
// Fachada de la capa de presentación: cablea los paneles (js/ui/*.js), expone los
// helpers compartidos (tooltip, secciones, i18n del DOM) y orquesta el render
// completo de un resultado. La lógica de cada panel vive en su propio módulo.
import { translations } from './i18n.js';
import { getLanguage } from './lang.js';
import { renderReputation } from './ui/reputationPanel.js';
import { renderAdvancedDNS } from './ui/advancedDnsPanel.js';
import { renderAwarenessVendors, analyzeHeaders } from './ui/awarenessPanel.js';
export { renderReputation, renderAdvancedDNS, renderAwarenessVendors, analyzeHeaders };
import { renderScorePanel, renderScoreBreakdown } from './ui/scorePanel.js';
import { renderSummaryPanel } from './ui/summaryPanel.js';
import { renderMxPanel, renderProviderPanel, renderSecurityLayersPanel } from './ui/mxPanel.js';
import { renderSpfPanel } from './ui/spfPanel.js';
import { renderDmarcPanel } from './ui/dmarcPanel.js';
import { renderDkimBimiPanel } from './ui/dkimBimiPanel.js';

/**
 * @param {string} domain  patrón a reconocer (dominio del include SPF o raíz del MX)
 * @param {'spf'|'mx'} list  lista del diccionario a la que se añadirá. Un MX y un
 *   include SPF no son intercambiables: el MX prueba flujo de correo entrante y el
 *   include solo autorización de envío, y cada uno se consulta por su lado.
 */
export function openKbModal(domain, list = 'spf') {
    const modal = document.getElementById('add-kb-modal');
    const target = list === 'mx' ? 'mx' : 'spf';
    const select = document.getElementById('kb-category');
    document.getElementById('kb-domain').value = domain;
    document.getElementById('kb-name').value = '';
    // Las categorías no son intercambiables: a un MX no se le puede asignar
    // "Marketing" o "Firmas de email"; solo proveedor, SEG o ICES. Se ocultan las
    // que no apliquen en vez de ofrecer opciones que producirían una entrada inválida.
    for (const option of select.options) {
        const only = option.dataset.kbFor;
        option.hidden = !!only && only !== target;
        option.disabled = option.hidden;
    }
    select.value = target === 'mx' ? 'seg' : 'marketing';
    modal.dataset.kbList = target;
    modal.classList.remove('hidden');
    document.getElementById('kb-name').focus();
}

export function closeKbModal() {
    document.getElementById('add-kb-modal').classList.add('hidden');
}

// Listener delegado para los botones "Añadir a BD" de la tabla SPF. El dominio
// viaja en data-kb-domain (escapado como atributo HTML), nunca en un onclick
// inline: los valores vienen del registro SPF remoto y podrían inyectar JS.
document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-kb-domain]');
    if (btn) openKbModal(btn.dataset.kbDomain, btn.dataset.kbList || 'spf');
});

// ===== Tooltips accesibles =====
// El sistema original solo respondía al ratón: quien navega con teclado o desde un
// móvil nunca veía la ayuda didáctica, que es media gracia de la herramienta. Ahora
// también se muestra al enfocar (focusin), se cierra con Escape y se anuncia a los
// lectores de pantalla vía aria-describedby.
let _tooltipEl = null;
const TOOLTIP_ID = 'tooltip-helper';
let _describedTrigger = null;

function hideTooltip() {
    if (!_tooltipEl) return;
    _tooltipEl.classList.add('hidden');
    if (_describedTrigger) {
        _describedTrigger.removeAttribute('aria-describedby');
        _describedTrigger = null;
    }
}

function showTooltip(trigger, position) {
    const text = trigger.getAttribute('data-tooltip');
    // Un data-tooltip vacío (atributo presente pero sin texto) tiene que OCULTAR el
    // tooltip: si solo se retornara, quedaría visible el del elemento anterior.
    if (!text) { hideTooltip(); return; }
    const el = getTooltipEl();
    el.textContent = text;
    el.classList.remove('hidden');
    if (_describedTrigger && _describedTrigger !== trigger) _describedTrigger.removeAttribute('aria-describedby');
    trigger.setAttribute('aria-describedby', TOOLTIP_ID);
    _describedTrigger = trigger;
    if (position) {
        placeTooltip(position.x, position.y);
    } else {
        // Con el foco no hay puntero: se ancla justo debajo del elemento.
        const r = trigger.getBoundingClientRect();
        placeTooltip(r.left, r.bottom + 4, { noFlip: true });
    }
}

function placeTooltip(clientX, clientY, { noFlip = false } = {}) {
    const margin = 12;
    const rect = _tooltipEl.getBoundingClientRect();
    let x = noFlip ? clientX : clientX + margin;
    let y = noFlip ? clientY : clientY + margin;
    if (x + rect.width > window.innerWidth - margin) x = Math.max(margin, window.innerWidth - rect.width - margin);
    if (y + rect.height > window.innerHeight - margin) y = clientY - rect.height - margin;
    _tooltipEl.style.left = `${x + window.scrollX}px`;
    _tooltipEl.style.top = `${y + window.scrollY}px`;
}

function getTooltipEl() {
    if (!_tooltipEl) {
        _tooltipEl = document.createElement('div');
        _tooltipEl.className = 'tooltip-helper hidden';
        _tooltipEl.id = TOOLTIP_ID;
        _tooltipEl.setAttribute('role', 'tooltip');
        document.body.appendChild(_tooltipEl);

        document.addEventListener('mouseover', (e) => {
            const trigger = e.target.closest('[data-tooltip]');
            if (!trigger) { hideTooltip(); return; }
            showTooltip(trigger, { x: e.clientX, y: e.clientY });
        });

        document.addEventListener('mousemove', (e) => {
            if (_tooltipEl.classList.contains('hidden')) return;
            placeTooltip(e.clientX, e.clientY);
        });

        document.addEventListener('mouseout', (e) => {
            if (!e.relatedTarget || !e.relatedTarget.closest('[data-tooltip]')) hideTooltip();
        });

        // Teclado: el foco muestra el tooltip y Escape lo cierra sin salir del campo.
        document.addEventListener('focusin', (e) => {
            const trigger = e.target.closest('[data-tooltip]');
            if (trigger) showTooltip(trigger, null);
            else hideTooltip();
        });
        document.addEventListener('focusout', hideTooltip);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') hideTooltip();
        });
        // Táctil: sin hover, un toque en el disparador lo muestra.
        document.addEventListener('click', (e) => {
            const trigger = e.target.closest('[data-tooltip]');
            if (trigger) showTooltip(trigger, null);
        });
    }
    return _tooltipEl;
}
// Ensure tooltip element exists on load
document.addEventListener('DOMContentLoaded', () => getTooltipEl());

export function showSection(id) {
    ['loading-section', 'error-section', 'results-section'].forEach(s => {
        document.getElementById(s).classList.add('hidden');
    });
    if (id) document.getElementById(id).classList.remove('hidden');
}

export function setStep(stepId, state) {
    const el = document.getElementById(stepId);
    if (!el) return;
    el.classList.remove('active', 'done');
    if (state) el.classList.add(state);
    const check = el.querySelector('.check-icon');
    if (check) {
        if (state === 'done') check.classList.remove('hidden');
        else check.classList.add('hidden');
    }
}

// renderSPFTree se ha trasladado a ui/spfPanel.js (único consumidor). Se re-exporta
// desde aquí para no romper a quien lo importe desde './ui.js'.
export { renderSPFTree } from './ui/spfPanel.js';

// Banderas del selector de idioma: SVG estático y propio (sin datos externos).
const FLAG_SVG = {
    es: '<svg viewBox="0 0 3 2" width="20" height="13.3"><rect width="3" height="2" fill="#AD1519"/><rect height="1" y="0.5" width="3" fill="#FABD00"/></svg>',
    en: '<svg viewBox="0 0 60 30" width="20" height="10"><path fill="#012169" d="M0 0h60v30H0z"/><path fill="#FFF" d="m0 0 60 30h-7L0 3.5zM0 30 60 0h-7L0 26.5zM60 30 0 0h7l53 26.5zM60 0 0 30h7l53-26.5zM30 0h-6v30h6zm-30 12h60v6H0z"/><path fill="#FFF" d="M27 0h6v30h-6zm-27 12h60v6H0z"/><path fill="#C8102E" d="M28 0h4v30h-4zm-28 13h60v4H0z"/></svg>'
};

export function translateDOM() {
    const lang = getLanguage();
    const t = translations[lang];
    if (!t) return;

    // Mantener <html lang> sincronizado con el idioma activo: los lectores de
    // pantalla aplican la fonética correcta y los buscadores indexan bien.
    if (document.documentElement) document.documentElement.lang = lang;

    // Elements with data-i18n
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (t[key]) {
            const pulseDot = el.querySelector('.pulse-dot');
            const svg = el.querySelector('svg');
            
            if (pulseDot || svg) {
                let hasUpdatedText = false;
                for (const node of el.childNodes) {
                    if (node.nodeType === Node.TEXT_NODE && node.textContent.trim() !== '') {
                        node.textContent = t[key];
                        hasUpdatedText = true;
                    }
                }
                if (!hasUpdatedText) {
                    const savedElements = [];
                    if (pulseDot) savedElements.push(pulseDot);
                    if (svg) savedElements.push(svg);
                    
                    el.innerHTML = '';
                    savedElements.forEach(se => el.appendChild(se));
                    if (savedElements.length > 0) {
                        el.appendChild(document.createTextNode(' '));
                    }
                    el.appendChild(document.createTextNode(t[key]));
                }
            } else {
                if (t[key].includes('<') && t[key].includes('>')) {
                    el.innerHTML = t[key];
                } else {
                    el.textContent = t[key];
                }
            }
        }
    });

    // Titles
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (t[key]) {
            el.setAttribute('title', t[key]);
        }
    });

    // Placeholders
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (t[key]) {
            el.setAttribute('placeholder', t[key]);
        }
    });

    // aria-label: los lectores de pantalla anuncian este texto, así que también
    // tiene que cambiar de idioma (antes quedaba fijo en español).
    document.querySelectorAll('[data-i18n-aria-label]').forEach(el => {
        const key = el.getAttribute('data-i18n-aria-label');
        if (t[key]) {
            el.setAttribute('aria-label', t[key]);
        }
    });

    // Update Language Selector button state (flag, text code)
    const btnFlag = document.getElementById('lang-btn-flag');
    const btnText = document.getElementById('lang-btn-text');
    
    if (btnText) btnText.textContent = lang.toUpperCase();
    if (btnFlag) {
        if (lang === 'es') {
            btnFlag.innerHTML = FLAG_SVG.es;
        } else {
            btnFlag.innerHTML = FLAG_SVG.en;
        }
    }

    // Update active class in selector dropdown list
    document.querySelectorAll('.lang-dropdown__item').forEach(item => {
        if (item.getAttribute('data-lang') === lang) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

export function renderResults(domain, result) {
    const lang = getLanguage();
    const t = translations[lang];

    renderScorePanel(result);
    renderScoreBreakdown(result);
    renderSummaryPanel(domain, result);
    renderMxPanel(domain, result);
    renderProviderPanel(result);
    renderSecurityLayersPanel(domain, result);
    renderSpfPanel(result);
    renderDmarcPanel(result);
    renderDkimBimiPanel(result);
    renderReputation(result.rblResults, lang, t);
    renderAdvancedDNS(result, lang, t);
    renderAwarenessVendors(result.awarenessResult || null, lang, t);
}

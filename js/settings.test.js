// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest';
import { getSettings, saveSettings, resetSettingsCache, resolverChain, DEFAULT_SETTINGS, primaryResolverOrigin } from './settings.js';

describe('settings', () => {
    beforeEach(() => {
        localStorage.clear();
        resetSettingsCache();
    });

    it('parte de los valores por defecto: proxy CORS apagado', () => {
        expect(getSettings().allowCorsProxy).toBe(false);
        expect(getSettings().resolver).toBe('google');
    });

    it('persiste y relee lo guardado', () => {
        saveSettings({ resolver: 'quad9', allowCorsProxy: true });
        resetSettingsCache();
        expect(getSettings()).toMatchObject({ resolver: 'quad9', allowCorsProxy: true });
    });

    it('ignora claves desconocidas de un localStorage manipulado', () => {
        localStorage.setItem('esc_settings', JSON.stringify({ resolver: 'cloudflare', evil: 'x' }));
        resetSettingsCache();
        const s = getSettings();
        expect(s.resolver).toBe('cloudflare');
        expect(s.evil).toBeUndefined();
    });

    it('se recupera de un localStorage corrupto', () => {
        localStorage.setItem('esc_settings', '{no es json');
        resetSettingsCache();
        expect(getSettings()).toEqual(DEFAULT_SETTINGS);
    });

    it('la cadena por defecto empieza por Google y tiene respaldo', () => {
        const chain = resolverChain('ex.com', 'TXT');
        expect(chain[0].url).toContain('dns.google');
        expect(chain.length).toBeGreaterThan(1);
    });

    it('el resolver elegido va primero', () => {
        saveSettings({ resolver: 'cloudflare' });
        expect(resolverChain('ex.com', 'TXT')[0].url).toContain('cloudflare');
    });

    it('un resolver propio no lleva respaldo público', () => {
        saveSettings({ resolver: 'custom', customResolverUrl: 'https://dns.interno.local/resolve/' });
        const chain = resolverChain('ex.com', 'TXT');
        expect(chain).toHaveLength(1);
        expect(chain[0].url).toBe('https://dns.interno.local/resolve?name=ex.com&type=TXT');
    });

    it('un resolver desconocido cae al de por defecto', () => {
        saveSettings({ resolver: 'inventado' });
        expect(resolverChain('ex.com', 'TXT')[0].url).toContain('dns.google');
    });

    it('Google DoH va sin ECS: la red del auditor no llega a los DNS del dominio auditado', () => {
        expect(resolverChain('ex.com', 'TXT')[0].url).toContain('edns_client_subnet=0.0.0.0/0');
    });

    it('por defecto no se contacta con los servidores del dominio auditado', () => {
        expect(getSettings().contactAuditedHosts).toBe(false);
    });

    it('el logo BIMI se carga por defecto y se puede apagar aparte', () => {
        expect(getSettings().loadBimiLogos).toBe(true);
        saveSettings({ loadBimiLogos: false });
        resetSettingsCache();
        expect(getSettings().loadBimiLogos).toBe(false);
        expect(getSettings().contactAuditedHosts).toBe(false);
    });

    it('escapa el nombre consultado en la URL', () => {
        const chain = resolverChain('ex ample.com', 'TXT');
        expect(chain[0].url).toContain('ex%20ample.com');
    });
});

describe('primaryResolverOrigin (preconnect)', () => {
    beforeEach(() => { resetSettingsCache(); saveSettings({ ...DEFAULT_SETTINGS }); });

    it('el origen del resolver que se usará primero', () => {
        expect(primaryResolverOrigin()).toBe('https://dns.google');
        saveSettings({ resolver: 'quad9' });
        expect(primaryResolverOrigin()).toBe('https://dns.quad9.net:5053');
        saveSettings({ resolver: 'custom', customResolverUrl: 'https://dns.interno.local/resolve?x=1' });
        expect(primaryResolverOrigin()).toBe('https://dns.interno.local');
    });

    it('null con una URL propia mal formada', () => {
        saveSettings({ resolver: 'custom', customResolverUrl: 'no es una url' });
        expect(primaryResolverOrigin()).toBeNull();
    });

    it('la consulta del tenant de Microsoft viene activada por defecto', () => {
        expect(getSettings().lookupEntraTenant).toBe(true);
    });
});

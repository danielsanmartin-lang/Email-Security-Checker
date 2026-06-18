import { describe, it, expect } from 'vitest';
import { _ipInCidr } from './awarenessDetector.js';

describe('_ipInCidr', () => {
    it('coincide IPv4 dentro de CIDR', () => {
        expect(_ipInCidr('23.21.109.197', '23.21.109.0/24')).toBe(true);
        expect(_ipInCidr('23.21.110.1', '23.21.109.0/24')).toBe(false);
    });
    it('coincide IPv4 exacta', () => {
        expect(_ipInCidr('1.2.3.4', '1.2.3.4')).toBe(true);
    });
    it('coincide IPv6 dentro de CIDR', () => {
        expect(_ipInCidr('2001:db8::1', '2001:db8::/32')).toBe(true);
        expect(_ipInCidr('2001:db9::1', '2001:db8::/32')).toBe(false);
    });
    it('coincide IPv6 comprimida exacta', () => {
        expect(_ipInCidr('2a01:111:f400::abcd', '2a01:111:f400::/48')).toBe(true);
    });
    it('no mezcla familias', () => {
        expect(_ipInCidr('1.2.3.4', '2001:db8::/32')).toBe(false);
        expect(_ipInCidr('2001:db8::1', '1.2.3.0/24')).toBe(false);
    });
});

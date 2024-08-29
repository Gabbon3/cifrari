import Buffer from './Vortex/Buffer.js';

class Poly1305 extends Buffer {
    constructor() { super(); }
    /* --- */
    static Mod = 1361129467683753853853498429727072845819n; // (2n ** 130n) - 5n;
    static Mask = 340282366920938463463374607431768211455n; // (2n ** 128n) - 1n;
    /**
     * Genera un tag utilizzando Poly1305
     * @param {String} M messaggio
     * @param {Uint8Array} K chiave
     */
    static auth(M, K) {
        M = Buffer.txt.Uint16_(M);
        const L = M.length;
        // ---
        const r = K.subarray(0, 16);
        const R = super.bigint._bytes(r);
        const s = K.subarray(16);
        const S = super.bigint._bytes(s);
        // ---
        let acc = 0n;
        // ---
        for (let i = 0; i < L; i++) {
            const n = BigInt(M[i]);
            acc = (acc + n) * R % this.Mod;
        }
        // ---
        acc += S;
        acc %= this.Mod;
        // -- applico la maschera per ottenere 128 bit
        acc &= this.Mask;
        // ---
        return super.bigint.bytes_(acc);
    }
}

export default Poly1305;
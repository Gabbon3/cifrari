import Buffer from './Buffer.js';

class ChaCha20HMAC256 extends Buffer {
    constructor() {
        super();
    }
    // -- "GabB0 flUTtu4nt3" -> firma dell algoritmo
    static F = new Uint32Array([1113743687, 1818632240, 1970558037, 863268404]);
    /**
     * Restituisce dei bytes casuali
     * @param {int} b numero di bytes da restituire
     * @param {boolean} as_base64 defalt su false per restituire i byte se no restituisce la stringa in base 64
     * @returns {Uint8Array | String}
     */
    static random_bytes(b, as_base64 = false) {
        if (b < 1) {
            return null;
        }
        // ---
        const bytes = crypto.getRandomValues(new Uint8Array(b));
        return as_base64 ? super.base64._bytes(bytes) : bytes;
    }
    /**
     * restituisce la firma di un messaggio usando HMAC-SHA-256
     * @param {Uint8Array} K chiave base 64
     * @param {string} M messaggio
     * @returns {ArrayBuffer} firma
     */
    static async hmac(K, M) {
        M = super.txt.bytes_(M);
        // -- importazione della chiave
        K = await crypto.subtle.importKey(
            "raw",
            K,
            { name: "HMAC", hash: { name: "SHA-256" } },
            false,
            ["sign"]
        );
        // -- calcolo della firma
        const S = await crypto.subtle.sign(
            "HMAC",
            K,
            M
        );
        // --
        return S;
    }
    /**
     * Esegue il metodo quarte round su 4 elementi del blocco
     * @param {Uint32Array} B 
     * @param {int} a 
     * @param {int} b 
     * @param {int} c 
     * @param {int} d 
     */
    static quarter_round(B, a, b, c, d) {
        B[a] += B[b];
        B[d] ^= B[a];
        B[d] = (B[d] << 16) | (B[d] >>> 16);
        // ---
        B[c] += B[d];
        B[b] ^= B[c];
        B[b] = (B[b] << 12) | (B[b] >>> 20);
        // ---
        B[a] += B[b];
        B[d] ^= B[a];
        B[d] = (B[d] << 8) | (B[d] >>> 24);
        // ---
        B[c] += B[d];
        B[b] ^= B[c];
        B[b] = (B[b] << 7) | (B[b] >>> 25);
    }
    /**
     * Combina la chiave il nonce e il contatore per ottenere una sequenza di 64 byte
     * @param {Uint32Array} K chiave
     * @param {Uint32Array} N nonce
     * @param {Uint32Array} C contatore
     */
    static stream(K, N, C) {
        // -- F = firma dell'algoritmo
        const F = this.F;
        // -- B = blocco da 64 byte
        const B = super.merge([F, K, N, C], 32);
        // ---
        for (let i = 0; i < 20; i++) {
            this.quarter_round(B, 0, 4, 8, 12);
            this.quarter_round(B, 1, 5, 9, 13);
            this.quarter_round(B, 2, 6, 10, 14);
            this.quarter_round(B, 3, 7, 11, 15);
            // ---
            this.quarter_round(B, 0, 5, 10, 15);
            this.quarter_round(B, 1, 6, 11, 12);
            this.quarter_round(B, 2, 7, 8, 13);
            this.quarter_round(B, 3, 4, 9, 14);
        }
        // ---
        return new Uint8Array(B.buffer);
    }
    /**
     * Genera combina la chiave il nonce e il contatore per ottenere una sequenza
     * di 64 byte
     * @param {Uint32Array} K chiave
     * @param {Uint32Array} N nonce
     * @param {int} L numero di byte da ottenere in uscita
     */
    static keystream(K, N, L) {
        // numero di byte generati
        let GL = 0;
        // -- contatore
        let C = new Uint32Array([0]);
        // -- inizializzo il keystream
        const KS = new Uint8Array(L);
        // ---
        while (GL < L) {
            const B = this.stream(K, N, C);
            // ---
            const byte_to_copy = Math.min(B.length, L - GL);
            // ---
            KS.set(B.subarray(0, byte_to_copy), GL);
            // ---
            GL += 64;
            C[0]++;
        }
        // ---
        return KS;
    }
    /**
     * Cifra Utilizzando ChaCha20
     * @param {String} M testo
     * @param {String} K chiave base 64
     * @param {String} N nonce base 64
     */
    static async encrypt(M, K, N = null) {
        M = super.txt.bytes_(M);
        const K8 = super.base64.bytes_(K);
        K = new Uint32Array(K8.buffer);
        N = new Uint32Array(N === null ? this.random_bytes(12).buffer : super.base64.bytes_(N).buffer);
        // -- calcolo la firma del messaggio
        const S = new Uint8Array(await this.hmac(K8, M));
        // ---
        const L = M.length;
        // ---
        const KS = this.keystream(K, N, L);
        // ---
        const EM = new Uint8Array(L);
        for (let i = 0; i < L; i++) {
            EM[i] = M[i] ^ KS[i];
        }
        // ---
        return {
            EM: Buffer.base64._bytes(Buffer.merge([EM, S], 8)),
            N: Buffer.base64._bytes(N)
        };
    }
    /**
     * Decifra Utilizzando ChaCha20
     * @param {String} EM testo cifrato in base64 (deve comprendere il nonce)
     * @param {String} K chiave base 64
     * @param {String} N nonce base 64
     */
    static async decrypt(EM, K, N) {
        // ---
        EM = super.base64.bytes_(EM);
        const SM = EM.subarray(EM.length - 32); // SM = firma contenuta nel messaggio
        EM = EM.subarray(0, EM.length - 32); // il messaggio cifrato
        // ---
        const K8 = super.base64.bytes_(K);
        K = new Uint32Array(K8.buffer);
        N = new Uint32Array(super.base64.bytes_(N).buffer);
        // ---
        const L = EM.length;
        // ---
        const KS = this.keystream(K, N, L);
        // ---
        const M = new Uint8Array(L);
        for (let i = 0; i < L; i++) {
            M[i] = EM[i] ^ KS[i];
        }
        // -- calcolo e verifico la firma
        const S = new Uint8Array(await this.hmac(K8, M));
        if (this.compare(SM, S) === false) return null;
        // ---
        return super.txt._bytes(M);
    }
    /**
     * Confronta due array di qualsiasi tipo verificando se sono uguali
     * @param {Array} a1 
     * @param {Array} a2 
     */
    static compare(a1, a2) {
        if (a1.length !== a2.length) return false;
        // ---
        const L = a1.length;
        for (let i = 0; i < L; i++) {
            if (a1[i] !== a2[i]) return false;
        }
        // ---
        return true;
    }
}

export default ChaCha20HMAC256;

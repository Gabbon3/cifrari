// Stream Cipher Gabbo
class SCG {
    /**
     * Restituisce dei bytes casuali
     * @param {Int} n_bytes 
     * @param {Boolean} as_base64 
     */
    static random_bytes(n_bytes, as_base64 = false) {
        if (n_bytes < 1) {
            return null;
        }
        // ---
        const bytes = crypto.getRandomValues(new Uint8Array(n_bytes));
        return as_base64 ? BufferUtils.base64._bytes(bytes) : bytes;
    }
    /**
     * Genera il keystream
     * @param {Base64String|Uint8Array} K chiave
     * @param {Base64String|Uint8Array} N nonce
     * @param {Int} L lunghezza in byte dell'output
     */
    static async keystream(K, N = "", L) {
        K = typeof K === 'string' ? BufferUtils.base64.bytes_(K) : K;
        N = typeof N === 'string' ? BufferUtils.base64.bytes_(N) : N;
        const stream = new Uint8Array(L);
        // ---
        let generated_length = 0;
        let counter = BufferUtils.number.little_endian(BufferUtils.merge.bytes(K, N));
        // ---
        while (generated_length < L) {
            counter++;
            const C = BufferUtils.merge.bytes(K, N, BufferUtils.txt.bytes_(`${counter}`)); // -- counter
            const hash = new Uint8Array(await this.sha256(C, false));
            const byte_to_copy = Math.min(hash.length, L - generated_length);
            // ---
            stream.set(hash.subarray(0, byte_to_copy), generated_length);
            // ---
            generated_length += hash.length;
        }
        // ---
        return stream;
    }
    /**
     * Cifra usando flusso
     * @param {String} M messaggio da cifrare
     * @param {Base64String} K chiave
     * @param {Base64String} N se nullo viene generato casualmente
     * @returns 
     */
    static async cifra(M, K, N = null) {
        // -- eseguo la firma del messaggio (S = sign)
        const S = new Uint8Array(await this.sha256(M + "." + K, false));
        // ---
        M = new TextEncoder().encode(M);
        const L = M.length;
        // -- genero se non è stato passato il Nonce
        N ??= this.random_bytes(12, true);
        // -- genero la KeyStream
        const KS = await this.keystream(K, N, L);
        // -- eseguo lo xor
        let EM = new Uint8Array(L);
        for (let i = 0; i < L; i++) {
            EM[i] = M[i] ^ KS[i];
        }
        // -- concateno il messaggio cifrato con la firma
        EM = BufferUtils.merge.bytes(S, EM);
        // ---
        return {
            EM: BufferUtils.base64._bytes(EM),
            N: N
        }
    }
    /**
     * Decifra usando flusso
     * @param {String} EM messaggio da decifrare
     * @param {Base64String} K chiave
     * @param {Base64String} N 
     * @returns 
     */
    static async decifra(EM, K, N) {
        EM = BufferUtils.base64.bytes_(EM);
        // --- recupero la firma e il messaggio
        const S = BufferUtils.base64._bytes(EM.subarray(0, 32));
        EM = EM.subarray(32);
        // ---
        const L = EM.length;
        // -- genero la KeyStream
        const KS = await this.keystream(K, N, L);
        // -- eseguo lo xor
        let M = new Uint8Array(L);
        for (let i = 0; i < L; i++) {
            M[i] = EM[i] ^ KS[i];
        }
        M = new TextDecoder().decode(M);
        // -- verifico la firma
        const S1 = await this.sha256(M + "." + K, true);
        if (S1 !== S) M = false;
        // ---
        return M;
    }
    /**
     * Esegue l hash di una stringa con SHA256
     * @param {String} data stringa da hashare
     * @param {Bool} as_base64 false restituisce il buffer
     * @returns 
     */
    static async sha256(data, as_base64 = true) {
        if (typeof data === 'string') data = new TextEncoder().encode(data);
        const hash = await crypto.subtle.digest("SHA-256", data);
        return as_base64 ? BufferUtils.base64._bytes(hash) : hash;
    }
}

const M = "Ciao, come stai?";
const K = SCG.random_bytes(32, true);

async function test() {
    const start = performance.now();
    const EM = await SCG.cifra(M, K);
    const end = performance.now();
    console.log(EM);
    console.log((end - start) + "ms");
    // ---
    const inversa = await SCG.decifra(EM.EM, K, EM.N);
    console.log(inversa);
}

window.onload = async () => {
    await test();
};

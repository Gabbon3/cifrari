class Buffer {
    static base64 = {
        /**
         * Converte una stringa base64 in un Uint8Array
         * @param {string} base64 
         * @returns {Uint8Array}
         */
        bytes_(base64) {
            let bin = atob(base64);
            let bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) {
                bytes[i] = bin.charCodeAt(i);
            }
            return bytes;
        },
        /**
         * Converte un Uint8Array in una stringa base64
         * @param {Uint8Array} buffer 
         * @returns {string}
         */
        _bytes(buffer) {
            let bin = "";
            const bytes = new Uint8Array(buffer.buffer);
            for (let i = 0; i < bytes.byteLength; i++) {
                bin += String.fromCharCode(bytes[i]);
            }
            return window.btoa(bin);
        },
    };

    static hex = {
        /**
         * Converte una stringa esadecimale in una stringa di testo
         * @param {string} hex_string 
         * @returns 
         */
        _hex(hex_string) {
            return hex_string
                .match(/.{1,2}/g)
                .map((byte) => String.fromCharCode(parseInt(byte, 16)))
                .join("");
        },
        /**
         * Converte una stringa di testo in una stringa esadecimale
         * @param {string} text 
         * @returns {string}
         */
        hex_(text) {
            return Array.from(text)
                .map((char) => char.charCodeAt(0).toString(16).padStart(2, '0'))
                .join("");
        },
        /**
         * Converte una stringa esadecimale in un Uint8Array
         * @param {string} hex 
         * @returns {Uint8Array}
         */
        bytes_(hex) {
            hex = hex.replace(/\s+/g, '').toLowerCase();
            if (hex.length % 2 !== 0) {
                throw new Error('Hex string must have an even length');
            }
            const length = hex.length / 2;
            const array = new Uint8Array(length);
            for (let i = 0; i < length; i++) {
                array[i] = parseInt(hex.substr(i * 2, 2), 16);
            }
            return array;
        },
        /**
         * Converte un Uint8Array in una stringa esadecimale
         * @param {string} array 
         * @returns {string}
         */
        _bytes(array) {
            return Array.from(array)
                .map(byte => byte.toString(16).padStart(2, '0'))
                .join('');
        },
    };

    static txt = {
        /**
         * Converte una stringa di testo in un Uint8Array
         * @param {string} txt 
         * @returns {Uint8Array}
         */
        bytes_(txt) {
            return new TextEncoder().encode(txt);
        },
        /**
         * Converte un Uint8Array in una stringa di testo
         * @param {Uint8Array} buffer 
         * @returns {string}
         */
        _bytes(buffer) {
            return new TextDecoder().decode(buffer);
        },
    };

    static bigint = {
        /**
         * Converte un Uint8Array in un BigInt
         * @param {Uint8Array} buffer 
         * @returns {BigInt}
         */
        _bytes(byte) {
            let n = 0n;
            const L = byte.length;
            // ---
            for (let i = 0; i < L; i++) {
                n = (n << 8n) | BigInt(byte[i]);
            }
            // ---
            return n;
        },
        /**
         * Converte un BigInt in un Uint8Array
         * @param {BigInt} n 
         * @returns {Uint8Array}
         */
        bytes_(n) {
            const L = Math.ceil(n.toString(2).length / 8);
            // ---
            const B = new Uint8Array(L);
            for (let i = 0; i < L; i++) {
                B[i] = Number(n & 255n);
                n >>= 8n;
            }
            // ---
            return B.reverse();
        }
    };

    static merge(buffers, size) {
        // -- ottengo la lunghezza totale
        let length = 0;
        for (const buffer of buffers) {
            length += buffer.length;
        }
        // -- unisci tutti gli array
        let merged_array;
        // ---
        switch (size) {
            case 8:
                merged_array = new Uint8Array(length);
                break;
            case 16:
                merged_array = new Uint16Array(length);
                break;
            case 32:
                merged_array = new Uint32Array(length);
                break;
            default:
                throw new Error("Invalid size");
        }
        // ---
        let offset = 0;
        for (const buffer of buffers) {
            merged_array.set(buffer, offset);
            offset += buffer.length;
        }
        // --
        return merged_array;
    }

    /**
     * Compara due Buffer verificando se sono uguali
     * @param {Array} a 
     * @param {Array} b 
     * @returns 
     */
    static compare(a, b) {
        if (a.length != b.length) throw new Error("Invalid size a is different than b");
        // ---
        const L = a.length;
        // ---
        for (let i = 0; i < L; i++) {
            if (a[i] !== b[i]) return false;
        }
        // ---
        return true;
    }
}

export default Buffer;
class Buffer {
    static base64 = {
        /**
         * Converte una stringa base64 in un Uint8Array
         * @param {string} base64 
         * @returns {Uint8Array}
         */
        bytes_(base64) {
            let binaryString = atob(base64);
            let bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        },
        /**
         * Converte un Uint8Array in una stringa base64
         * @param {Uint8Array} buffer 
         * @returns {string}
         */
        _bytes(buffer) {
            let binary = "";
            const bytes = new Uint8Array(buffer.buffer);
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return window.btoa(binary);
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
}

export default Buffer;
import Vortex from './Vortex.js';
import m from './m.js';

window.onload = () => {
    const M = `Ciao come stai? 🐘`;
    const K = Vortex.random_bytes(32, true);
    console.log("K: " + K);
    const s = performance.now();
    const EM = Vortex.encrypt(M, K);
    const e = performance.now();
    console.log(EM);
    console.log(e-s, "ms");
    console.log("---");
    const OM = Vortex.decrypt(EM.EM, K, EM.N);
    console.log(OM);
}
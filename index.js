import Vortex from './Vortex/Vortex.js';
import Buffer from './Vortex/Buffer.js';
import Poly1305 from './Poly1305.js';
import m from './m.js';

window.onload = () => {
    const M = `Ciao come stai? 🐘`;
    const K = Vortex.random_bytes(32, true);
    console.log("K:");
    console.log(K);
    const s = performance.now();
    const EM = Vortex.encrypt(m, K);
    const e = performance.now();
    console.log(EM);
    console.log(e-s, "ms");
    console.log("---");
    // const OM = Vortex.decrypt(EM.EM, K, EM.N);
    // console.log(OM);
}
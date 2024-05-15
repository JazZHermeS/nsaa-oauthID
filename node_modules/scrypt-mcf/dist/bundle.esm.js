function e$1(e,r=!1,t=!0){let n="";n=(e=>{const r=[];for(let t=0;t<e.length;t+=32768)r.push(String.fromCharCode.apply(null,e.subarray(t,t+32768)));return btoa(r.join(""))})("string"==typeof e?(new TextEncoder).encode(e):new Uint8Array(e));return r&&(n=function(e){return e.replace(/\+/g,"-").replace(/\//g,"_")}(n)),t||(n=n.replace(/=/g,"")),n}function r$2(e,r=!1){{let t=!1;if(/^[0-9a-zA-Z_-]+={0,2}$/.test(e))t=!0;else if(!/^[0-9a-zA-Z+/]*={0,2}$/.test(e))throw new Error("Not a valid base64 input");t&&(e=e.replace(/-/g,"+").replace(/_/g,"/").replace(/=/g,""));const n=new Uint8Array(atob(e).split("").map((e=>e.charCodeAt(0))));return r?(new TextDecoder).decode(n):n}}

const e={"SHA-1":{outputLength:20,blockSize:64},"SHA-256":{outputLength:32,blockSize:64},"SHA-384":{outputLength:48,blockSize:128},"SHA-512":{outputLength:64,blockSize:128}};function t$1(t,a,o,i,s="SHA-256"){return new Promise(((u,c)=>{s in e||c(new RangeError(`Valid hash algorithm values are any of ${Object.keys(e).toString()}`)),"string"==typeof t?t=(new TextEncoder).encode(t):t instanceof ArrayBuffer?t=new Uint8Array(t):ArrayBuffer.isView(t)||c(RangeError("P should be string, ArrayBuffer, TypedArray, DataView")),"string"==typeof a?a=(new TextEncoder).encode(a):a instanceof ArrayBuffer?a=new Uint8Array(a):ArrayBuffer.isView(a)?a=new Uint8Array(a.buffer,a.byteOffset,a.byteLength):c(RangeError("S should be string, ArrayBuffer, TypedArray, DataView")),crypto.subtle.importKey("raw",t,"PBKDF2",!1,["deriveBits"]).then((f=>{const y={name:"PBKDF2",hash:s,salt:a,iterations:o};crypto.subtle.deriveBits(y,f,8*i).then((e=>u(e)),(f=>{(async function(t,a,o,i,s){if(!(s in e))throw new RangeError(`Valid hash algorithm values are any of ${Object.keys(e).toString()}`);if(!Number.isInteger(o)||o<=0)throw new RangeError("c must be a positive integer");const u=e[s].outputLength;if(!Number.isInteger(i)||i<=0||i>=(2**32-1)*u)throw new RangeError("dkLen must be a positive integer < (2 ** 32 - 1) * hLen");const c=Math.ceil(i/u),f=i-(c-1)*u,y=new Array(c);0===t.byteLength&&(t=new Uint8Array(e[s].blockSize));const w=await crypto.subtle.importKey("raw",t,{name:"HMAC",hash:{name:s}},!0,["sign"]),g=async function(e,t){const r=await crypto.subtle.sign("HMAC",e,t);return new Uint8Array(r)};for(let e=0;e<c;e++)y[e]=await h(w,a,o,e+1);async function h(e,t,a,o){function i(e){const t=new ArrayBuffer(4);return new DataView(t).setUint32(0,e,!1),new Uint8Array(t)}const s=await g(e,r$1(t,i(o)));let u=s;for(let t=1;t<a;t++)u=await g(e,u),n$1(s,u);return s}return y[c-1]=y[c-1].slice(0,f),r$1(...y).buffer})(t,a,o,i,s).then((e=>u(e)),(e=>c(e)));}));}),(e=>c(e)));}))}function r$1(...e){const t=e.reduce(((e,t)=>e+t.length),0);if(0===e.length)throw new RangeError("Cannot concat no arrays");const r=new Uint8Array(t);let n=0;for(const t of e)r.set(t,n),n+=t.length;return r}function n$1(e,t){for(let r=0;r<e.length;r++)e[r]^=t[r];}

const r=function(e){function r(e,r){return e<<r|e>>>32-r}const t=e.slice(0);for(let e=8;e>0;e-=2)t[4]^=r(t[0]+t[12],7),t[8]^=r(t[4]+t[0],9),t[12]^=r(t[8]+t[4],13),t[0]^=r(t[12]+t[8],18),t[9]^=r(t[5]+t[1],7),t[13]^=r(t[9]+t[5],9),t[1]^=r(t[13]+t[9],13),t[5]^=r(t[1]+t[13],18),t[14]^=r(t[10]+t[6],7),t[2]^=r(t[14]+t[10],9),t[6]^=r(t[2]+t[14],13),t[10]^=r(t[6]+t[2],18),t[3]^=r(t[15]+t[11],7),t[7]^=r(t[3]+t[15],9),t[11]^=r(t[7]+t[3],13),t[15]^=r(t[11]+t[7],18),t[1]^=r(t[0]+t[3],7),t[2]^=r(t[1]+t[0],9),t[3]^=r(t[2]+t[1],13),t[0]^=r(t[3]+t[2],18),t[6]^=r(t[5]+t[4],7),t[7]^=r(t[6]+t[5],9),t[4]^=r(t[7]+t[6],13),t[5]^=r(t[4]+t[7],18),t[11]^=r(t[10]+t[9],7),t[8]^=r(t[11]+t[10],9),t[9]^=r(t[8]+t[11],13),t[10]^=r(t[9]+t[8],18),t[12]^=r(t[15]+t[14],7),t[13]^=r(t[12]+t[15],9),t[14]^=r(t[13]+t[12],13),t[15]^=r(t[14]+t[13],18);for(let r=0;r<16;r++)e[r]=t[r]+e[r];},t=function(e,r){for(let t=0;t<e.length;t++)e[t]^=r[t];},n=function(e){const n=e.byteLength/128,i=16*(2*n-1),o=e.slice(i,i+16),f=new Uint32Array(e.length/2);let s=!0;for(let i=0;i<2*n;i++){const n=16*i,a=e.subarray(n,n+16);t(o,a),r(o);const u=16*(i>>1);if(s)for(let r=0;r<16;r++)e[u+r]=o[r];else for(let e=0;e<16;e++)f[u+e]=o[e];s=!s;}const a=16*n;for(let r=0;r<a;r++)e[a+r]=f[r];},i=function(e,r){const i=e.byteLength/128,o=new Array(r);for(let t=0;t<r;t++)o[t]=e.slice(0),n(e);function f(e){const t=64*(2*i-1);return new DataView(e.buffer,t,64).getUint32(0,!0)%r}for(let i=0;i<r;i++){const r=f(e);t(e,o[r]),n(e);}},o=async function(r,t,n,o){if("string"==typeof r)r=(new TextEncoder).encode(r);else if(r instanceof ArrayBuffer)r=new Uint8Array(r);else if(!ArrayBuffer.isView(r))throw RangeError("P should be string, ArrayBuffer, TypedArray, DataView");if("string"==typeof t)t=(new TextEncoder).encode(t);else if(t instanceof ArrayBuffer)t=new Uint8Array(t);else if(!ArrayBuffer.isView(t))throw RangeError("S should be string, ArrayBuffer, TypedArray, DataView");if(!Number.isInteger(n)||n<=0||n>137438953440)throw RangeError("dkLen is the intended output length in octets of the derived key; a positive integer less than or equal to (2^32 - 1) * hLen where hLen is 32");const f=void 0!==o&&void 0!==o.N?o.N:131072,s=void 0!==o&&void 0!==o.r?o.r:8,a=void 0!==o&&void 0!==o.p?o.p:1;if(!Number.isInteger(f)||f<=0||0!=(f&f-1))throw RangeError("N must be a power of 2");if(!Number.isInteger(s)||s<=0||!Number.isInteger(a)||a<=0||a*s>1073741823.75)throw RangeError("Parallelization parameter p and blocksize parameter r must be positive integers satisfying p ≤ (2^32− 1) * hLen / MFLen where hLen is 32 and MFlen is 128 * r.");const u=await t$1(r,t,1,128*a*s),c=new Uint32Array(u);for(let e=0;e<a;e++){const r=32*s,t=e*r,n=c.slice(t,t+r);i(n,f);for(let e=0;e<32*s;e++)c[t+e]=n[e];}return await t$1(r,c,1,n)},f=function(e=16){if(!Number.isInteger(e)||e<0)throw new RangeError("length must be integer >= 0");return 0===e?new ArrayBuffer(0):crypto.getRandomValues(new Uint8Array(e)).buffer};

async function hash(password, options) {
    const scryptParams = {
        logN: 17,
        r: 8,
        p: 1,
        ...options?.scryptParams
    };
    const scryptPbkdfParams = {
        N: 2 ** scryptParams.logN,
        r: scryptParams.r,
        p: scryptParams.p
    };
    const S = (options?.saltBase64NoPadding !== undefined) ? r$2(options.saltBase64NoPadding) : f();
    const SBase64 = e$1(S, false, false);
    const derivedKeyLength = options?.derivedKeyLength ?? 32;
    const hash = e$1(await o(password, S, derivedKeyLength, scryptPbkdfParams), false, false);
    return `$scrypt$ln=${scryptParams.logN},r=${scryptParams.r},p=${scryptParams.p}$${SBase64}$${hash}`;
}
async function verify(password, mcf) {
    const regex = /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})\$([a-zA-Z0-9/+]{22})\$([a-zA-Z0-9/+]{22,})$/g;
    const matches = [...mcf.matchAll(regex)];
    if (matches.length !== 1) {
        throw new Error('Invalid MCFstring format');
    }
    const logN = Number(matches[0][1]);
    const r = Number(matches[0][2]);
    const p = Number(matches[0][3]);
    const S = matches[0][4];
    const derivedKeyLength = 2 ** (Math.floor(Math.log2(matches[0][5].length * 6)) - 3);
    const passwordMfc = await hash(password, {
        saltBase64NoPadding: S,
        scryptParams: { logN, r, p },
        derivedKeyLength
    });
    return passwordMfc === mcf;
}

export { hash, verify };

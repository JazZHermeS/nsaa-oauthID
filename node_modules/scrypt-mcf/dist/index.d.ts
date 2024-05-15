interface ScryptParams {
    logN?: number;
    r?: number;
    p?: number;
}
interface ScryptMcfOptions {
    saltBase64NoPadding?: string;
    derivedKeyLength?: number;
    scryptParams?: ScryptParams;
}
declare function hash(password: string, options?: ScryptMcfOptions): Promise<string>;
declare function verify(password: string, mcf: string): Promise<boolean>;

export { ScryptMcfOptions, ScryptParams, hash, verify };

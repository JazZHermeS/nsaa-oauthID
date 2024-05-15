export interface ScryptParams {
    logN?: number;
    r?: number;
    p?: number;
}
export interface ScryptMcfOptions {
    saltBase64NoPadding?: string;
    derivedKeyLength?: number;
    scryptParams?: ScryptParams;
}
export declare function hash(password: string, options?: ScryptMcfOptions): Promise<string>;
export declare function verify(password: string, mcf: string): Promise<boolean>;
//# sourceMappingURL=index.d.ts.map
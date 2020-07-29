/// <reference types="node" />
import { BinaryLike } from 'crypto';
import { RequestOptions } from 'https';
export declare function urlEncode(str: string): string;
export declare class SigningHttpRequest {
    method: string;
    url: URL;
    headers: Record<string, string>;
    body: any;
    constructor(method: string, url: string, headers?: Record<string, string>, body?: BinaryLike);
    private headerTime;
    findHeader(header: string): string | null;
    canonicalRequest(signedHeaders: Array<string>): string;
    canonicalURI(): string;
    canonicalQueryString(): string;
    canonicalHeaders(signedHeaders: Array<string>): string;
    signedHeaders(): string[];
    stringToSign(): string;
    signature(signingKey: string): string;
    authHeaderValue(ak: string, sk: string): string;
}
export declare class Signer {
    private key;
    private secret;
    constructor(key: string, secret: string);
    sign(r: SigningHttpRequest): RequestOptions;
}

import { createHmac, createHash, BinaryLike } from 'crypto';
import { RequestOptions } from 'https';

const ALGORITHM = 'SDK-HMAC-SHA256';
const HEADER_X_DATE = 'X-Sdk-Date';
const HEADER_AUTHORIZATION = 'Authorization';
const HEADER_CONTENT_SHA256 = 'x-sdk-content-sha256';

const hexTable = new Array(256);

for (let i = 0; i < 256; ++i) {
  hexTable[i] = '%' + ((i < 16 ? '0' : '') + i.toString(16)).toUpperCase();
}

// prettier-ignore
const noEscape = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0 - 15
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 - 31
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, // 32 - 47
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 48 - 63
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 64 - 79
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, // 80 - 95
  0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 96 - 111
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0  // 112 - 127
];

function hmacsha256(keyByte: BinaryLike, message: BinaryLike) {
  return createHmac('SHA256', keyByte).update(message).digest().toString('hex');
}

function hexEncodeSHA256Hash(body: BinaryLike) {
  return createHash('SHA256').update(body).digest().toString('hex');
}

export function urlEncode(str: string): string {
  let out = '';
  let lastPos = 0;

  for (let i = 0; i < str.length; ++i) {
    let c = str.charCodeAt(i);

    // ASCII
    if (c < 0x80) {
      if (noEscape[c] === 1) continue;
      if (lastPos < i) out += str.slice(lastPos, i);
      lastPos = i + 1;
      out += hexTable[c];
      continue;
    }

    if (lastPos < i) out += str.slice(lastPos, i);

    // Multi-byte characters ...
    if (c < 0x800) {
      lastPos = i + 1;
      out += hexTable[0xc0 | (c >> 6)] + hexTable[0x80 | (c & 0x3f)];
      continue;
    }

    if (c < 0xd800 || c >= 0xe000) {
      lastPos = i + 1;
      out += hexTable[0xe0 | (c >> 12)] + hexTable[0x80 | ((c >> 6) & 0x3f)] + hexTable[0x80 | (c & 0x3f)];
      continue;
    }
    // Surrogate pair
    ++i;

    if (i >= str.length) throw new URIError('ERR_INVALID_URI');

    const c2 = str.charCodeAt(i) & 0x3ff;

    lastPos = i + 1;
    c = 0x10000 + (((c & 0x3ff) << 10) | c2);
    out +=
      hexTable[0xf0 | (c >> 18)] +
      hexTable[0x80 | ((c >> 12) & 0x3f)] +
      hexTable[0x80 | ((c >> 6) & 0x3f)] +
      hexTable[0x80 | (c & 0x3f)];
  }

  if (lastPos === 0) return str;
  if (lastPos < str.length) return out + str.slice(lastPos);
  return out;
}

export class SigningHttpRequest {
  public method: string;
  public url: URL;
  public headers: Record<string, string>;
  public body: any;

  constructor(method: string, url: string, headers?: Record<string, string>, body?: BinaryLike) {
    this.method = method ?? '';
    this.url = new URL(url);
    this.headers = headers ?? {};

    this.headers['Host'] = this.url.host;
    this.headers[HEADER_X_DATE] = this.headers[HEADER_X_DATE] ?? this.headerTime();

    if (method !== 'PUT' && method !== 'PATCH' && method !== 'POST') {
      this.body = '';
    } else {
      this.body = body ?? '';
    }
  }

  private headerTime(): string {
    const twoChar = (s: number) => (s >= 10 ? '' + s : '0' + s);

    const date = new Date();
    return (
      '' +
      date.getUTCFullYear() +
      twoChar(date.getUTCMonth() + 1) +
      twoChar(date.getUTCDate()) +
      'T' +
      twoChar(date.getUTCHours()) +
      twoChar(date.getUTCMinutes()) +
      twoChar(date.getUTCSeconds()) +
      'Z'
    );
  }

  public findHeader(header: string): string | null {
    for (const k in this.headers) {
      if (k.toLowerCase() === header.toLowerCase()) {
        return this.headers[k];
      }
    }

    return null;
  }

  public canonicalRequest(signedHeaders: Array<string>): string {
    const hexencode = this.findHeader(HEADER_CONTENT_SHA256) ?? hexEncodeSHA256Hash(this.body);

    return (
      this.method +
      '\n' +
      this.canonicalURI() +
      '\n' +
      this.canonicalQueryString() +
      '\n' +
      this.canonicalHeaders(signedHeaders) +
      '\n' +
      signedHeaders.join(';') +
      '\n' +
      hexencode
    );
  }

  canonicalURI(): string {
    const pattens = decodeURI(this.url.pathname).split('/');
    const uri = [];
    for (const k in pattens) {
      const v = pattens[k];
      uri.push(urlEncode(v));
    }

    let urlpath = uri.join('/');
    if (urlpath[urlpath.length - 1] !== '/') {
      urlpath = urlpath + '/';
    }

    return urlpath;
  }

  public canonicalQueryString(): string {
    const keys: string[] = [];

    this.url.searchParams.forEach((_value: string, key: string) => {
      keys.push(key);
    });

    keys.sort();
    const a = [];

    for (const i in keys) {
      const key = urlEncode(keys[i]);
      const value = this.url.searchParams.get(keys[i]);

      if (!!value) {
        if (Array.isArray(value)) {
          value.sort();
          for (const iv in value) {
            a.push(key + '=' + urlEncode(value[iv]));
          }
        } else {
          a.push(key + '=' + urlEncode(value));
        }
      }
    }

    return a.join('&');
  }

  canonicalHeaders(signedHeaders: Array<string>): string {
    const headers: Record<string, string> = {};
    for (const key in this.headers) {
      headers[key.toLowerCase()] = this.headers[key];
    }

    const a = [];
    for (const i in signedHeaders) {
      const value = headers[signedHeaders[i]];
      a.push(signedHeaders[i] + ':' + value.trim());
    }

    return a.join('\n') + '\n';
  }

  public signedHeaders(): string[] {
    const a = [];
    for (const key in this.headers) {
      a.push(key.toLowerCase());
    }
    a.sort();
    return a;
  }

  public stringToSign(): string {
    const headerTime = this.findHeader(HEADER_X_DATE) as string;
    const signedHeaders = this.signedHeaders();
    const canonicalRequest = this.canonicalRequest(signedHeaders);
    const bytes = hexEncodeSHA256Hash(canonicalRequest);
    return ALGORITHM + '\n' + headerTime + '\n' + bytes;
  }

  public signature(signingKey: string): string {
    const stringToSign = this.stringToSign();
    return hmacsha256(signingKey, stringToSign);
  }

  public authHeaderValue(ak: string, sk: string): string {
    const signature = this.signature(sk);
    return (
      ALGORITHM + ' Access=' + ak + ', SignedHeaders=' + this.signedHeaders().join(';') + ', Signature=' + signature
    );
  }
}

export class Signer {
  private key: string;
  private secret: string;

  constructor(key: string, secret: string) {
    this.key = key;
    this.secret = secret;
  }

  public sign(r: SigningHttpRequest): RequestOptions {
    let queryString = r.canonicalQueryString();

    if (queryString !== '') {
      queryString = '?' + queryString;
    }

    const options: { hostname: string; path: string; method: string; headers: Record<string, string> } = {
      hostname: r.url.hostname,
      path: encodeURI(r.url.pathname) + queryString,
      method: r.method,
      headers: r.headers,
    };

    options.headers[HEADER_AUTHORIZATION] = r.authHeaderValue(this.key, this.secret);
    return options;
  }
}

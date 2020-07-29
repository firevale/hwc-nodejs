"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Signer = exports.SigningHttpRequest = exports.urlEncode = void 0;
var crypto_1 = require("crypto");
var ALGORITHM = 'SDK-HMAC-SHA256';
var HEADER_X_DATE = 'X-Sdk-Date';
var HEADER_AUTHORIZATION = 'Authorization';
var HEADER_CONTENT_SHA256 = 'x-sdk-content-sha256';
var hexTable = new Array(256);
for (var i = 0; i < 256; ++i) {
    hexTable[i] = '%' + ((i < 16 ? '0' : '') + i.toString(16)).toUpperCase();
}
// prettier-ignore
var noEscape = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0 // 112 - 127
];
function hmacsha256(keyByte, message) {
    return crypto_1.createHmac('SHA256', keyByte).update(message).digest().toString('hex');
}
function hexEncodeSHA256Hash(body) {
    return crypto_1.createHash('SHA256').update(body).digest().toString('hex');
}
function urlEncode(str) {
    var out = '';
    var lastPos = 0;
    for (var i = 0; i < str.length; ++i) {
        var c = str.charCodeAt(i);
        // ASCII
        if (c < 0x80) {
            if (noEscape[c] === 1)
                continue;
            if (lastPos < i)
                out += str.slice(lastPos, i);
            lastPos = i + 1;
            out += hexTable[c];
            continue;
        }
        if (lastPos < i)
            out += str.slice(lastPos, i);
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
        if (i >= str.length)
            throw new URIError('ERR_INVALID_URI');
        var c2 = str.charCodeAt(i) & 0x3ff;
        lastPos = i + 1;
        c = 0x10000 + (((c & 0x3ff) << 10) | c2);
        out +=
            hexTable[0xf0 | (c >> 18)] +
                hexTable[0x80 | ((c >> 12) & 0x3f)] +
                hexTable[0x80 | ((c >> 6) & 0x3f)] +
                hexTable[0x80 | (c & 0x3f)];
    }
    if (lastPos === 0)
        return str;
    if (lastPos < str.length)
        return out + str.slice(lastPos);
    return out;
}
exports.urlEncode = urlEncode;
var SigningHttpRequest = /** @class */ (function () {
    function SigningHttpRequest(method, url, headers, body) {
        var _a;
        this.method = method !== null && method !== void 0 ? method : '';
        this.url = new URL(url);
        this.headers = headers !== null && headers !== void 0 ? headers : {};
        this.headers['Host'] = this.url.host;
        this.headers[HEADER_X_DATE] = (_a = this.headers[HEADER_X_DATE]) !== null && _a !== void 0 ? _a : this.headerTime();
        if (method !== 'PUT' && method !== 'PATCH' && method !== 'POST') {
            this.body = '';
        }
        else {
            this.body = body !== null && body !== void 0 ? body : '';
        }
    }
    SigningHttpRequest.prototype.headerTime = function () {
        var twoChar = function (s) { return (s >= 10 ? '' + s : '0' + s); };
        var date = new Date();
        return ('' +
            date.getUTCFullYear() +
            twoChar(date.getUTCMonth() + 1) +
            twoChar(date.getUTCDate()) +
            'T' +
            twoChar(date.getUTCHours()) +
            twoChar(date.getUTCMinutes()) +
            twoChar(date.getUTCSeconds()) +
            'Z');
    };
    SigningHttpRequest.prototype.findHeader = function (header) {
        for (var k in this.headers) {
            if (k.toLowerCase() === header.toLowerCase()) {
                return this.headers[k];
            }
        }
        return null;
    };
    SigningHttpRequest.prototype.canonicalRequest = function (signedHeaders) {
        var _a;
        var hexencode = (_a = this.findHeader(HEADER_CONTENT_SHA256)) !== null && _a !== void 0 ? _a : hexEncodeSHA256Hash(this.body);
        return (this.method +
            '\n' +
            this.canonicalURI() +
            '\n' +
            this.canonicalQueryString() +
            '\n' +
            this.canonicalHeaders(signedHeaders) +
            '\n' +
            signedHeaders.join(';') +
            '\n' +
            hexencode);
    };
    SigningHttpRequest.prototype.canonicalURI = function () {
        var pattens = decodeURI(this.url.pathname).split('/');
        var uri = [];
        for (var k in pattens) {
            var v = pattens[k];
            uri.push(urlEncode(v));
        }
        var urlpath = uri.join('/');
        if (urlpath[urlpath.length - 1] !== '/') {
            urlpath = urlpath + '/';
        }
        return urlpath;
    };
    SigningHttpRequest.prototype.canonicalQueryString = function () {
        var keys = [];
        this.url.searchParams.forEach(function (_value, key) {
            keys.push(key);
        });
        keys.sort();
        var a = [];
        for (var i in keys) {
            var key = urlEncode(keys[i]);
            var value = this.url.searchParams.get(keys[i]);
            if (!!value) {
                if (Array.isArray(value)) {
                    value.sort();
                    for (var iv in value) {
                        a.push(key + '=' + urlEncode(value[iv]));
                    }
                }
                else {
                    a.push(key + '=' + urlEncode(value));
                }
            }
        }
        return a.join('&');
    };
    SigningHttpRequest.prototype.canonicalHeaders = function (signedHeaders) {
        var headers = {};
        for (var key in this.headers) {
            headers[key.toLowerCase()] = this.headers[key];
        }
        var a = [];
        for (var i in signedHeaders) {
            var value = headers[signedHeaders[i]];
            a.push(signedHeaders[i] + ':' + value.trim());
        }
        return a.join('\n') + '\n';
    };
    SigningHttpRequest.prototype.signedHeaders = function () {
        var a = [];
        for (var key in this.headers) {
            a.push(key.toLowerCase());
        }
        a.sort();
        return a;
    };
    SigningHttpRequest.prototype.stringToSign = function () {
        var headerTime = this.findHeader(HEADER_X_DATE);
        var signedHeaders = this.signedHeaders();
        var canonicalRequest = this.canonicalRequest(signedHeaders);
        var bytes = hexEncodeSHA256Hash(canonicalRequest);
        return ALGORITHM + '\n' + headerTime + '\n' + bytes;
    };
    SigningHttpRequest.prototype.signature = function (signingKey) {
        var stringToSign = this.stringToSign();
        return hmacsha256(signingKey, stringToSign);
    };
    SigningHttpRequest.prototype.authHeaderValue = function (ak, sk) {
        var signature = this.signature(sk);
        return (ALGORITHM + ' Access=' + ak + ', SignedHeaders=' + this.signedHeaders().join(';') + ', Signature=' + signature);
    };
    return SigningHttpRequest;
}());
exports.SigningHttpRequest = SigningHttpRequest;
var Signer = /** @class */ (function () {
    function Signer(key, secret) {
        this.key = key;
        this.secret = secret;
    }
    Signer.prototype.sign = function (r) {
        var queryString = r.canonicalQueryString();
        if (queryString !== '') {
            queryString = '?' + queryString;
        }
        var options = {
            hostname: r.url.hostname,
            path: encodeURI(r.url.pathname) + queryString,
            method: r.method,
            headers: r.headers,
        };
        options.headers[HEADER_AUTHORIZATION] = r.authHeaderValue(this.key, this.secret);
        return options;
    };
    return Signer;
}());
exports.Signer = Signer;

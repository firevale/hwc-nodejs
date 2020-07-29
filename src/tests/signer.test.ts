import { urlEncode, SigningHttpRequest, Signer } from '../signer';
import { CdnClient } from '../cdnClient';

test('encodeURI', () => {
  let s = '';
  for (let i = 0; i < 0x80; ++i) {
    s = s + urlEncode(String.fromCharCode(i));
  }

  expect(s).toBe(
    '%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15' +
      '%16%17%18%19%1A%1B%1C%1D%1E%1F%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-' +
      '.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D' +
      '%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%7F',
  );
});

test('generate http request signature', () => {
  const r = new SigningHttpRequest(
    'GET',
    'https://service.region.example.com/v1/77b6a44cba5143ab91d13ab9a8ff44fd/vpcs?marker=13551d6b-755d-4757-b956-536f674975c0&limit=2',
    { 'Content-Type': 'application/json', 'X-Sdk-Date': '20191115T033655Z' },
  );

  expect(r.canonicalURI()).toBe('/v1/77b6a44cba5143ab91d13ab9a8ff44fd/vpcs/');
  expect(r.canonicalQueryString()).toBe('limit=2&marker=13551d6b-755d-4757-b956-536f674975c0');
  expect(r.canonicalHeaders(r.signedHeaders())).toBe(
    'content-type:application/json\nhost:service.region.example.com\nx-sdk-date:20191115T033655Z\n',
  );
  expect(r.stringToSign()).toBe(
    'SDK-HMAC-SHA256\n20191115T033655Z\nb25362e603ee30f4f25e7858e8a7160fd36e803bb2dfe206278659d71a9bcd7a',
  );
  expect(r.signature('MFyfvK41ba2giqM7Uio6PznpdUKGpownRZlmVmHc')).toBe(
    '7be6668032f70418fcc22abc52071e57aff61b84a1d2381bb430d6870f4f6ebe',
  );
  expect(r.authHeaderValue('QTWAOYTTINDUT2QVKYUC', 'MFyfvK41ba2giqM7Uio6PznpdUKGpownRZlmVmHc')).toBe(
    'SDK-HMAC-SHA256 Access=QTWAOYTTINDUT2QVKYUC, SignedHeaders=content-type;host;x-sdk-date, ' +
      'Signature=7be6668032f70418fcc22abc52071e57aff61b84a1d2381bb430d6870f4f6ebe',
  );

  const s = new Signer('QTWAOYTTINDUT2QVKYUC', 'MFyfvK41ba2giqM7Uio6PznpdUKGpownRZlmVmHc');

  expect(s.sign(r)).toStrictEqual({
    hostname: 'service.region.example.com',
    method: 'GET',
    path: '/v1/77b6a44cba5143ab91d13ab9a8ff44fd/vpcs?limit=2&marker=13551d6b-755d-4757-b956-536f674975c0',
    headers: {
      Authorization:
        'SDK-HMAC-SHA256 Access=QTWAOYTTINDUT2QVKYUC, SignedHeaders=content-type;host;x-sdk-date, Signature=7be6668032f70418fcc22abc52071e57aff61b84a1d2381bb430d6870f4f6ebe',
      'Content-Type': 'application/json',
      Host: 'service.region.example.com',
      'X-Sdk-Date': '20191115T033655Z',
    },
  });
});

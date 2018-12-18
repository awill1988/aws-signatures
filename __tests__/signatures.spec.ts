import 'jest'
import HAMC_SHA256 from 'crypto-js/hmac-sha256';
import Hex from 'crypto-js/enc-hex';

describe('Encryption tests', () => {

  test('Can derive secret key', () => {
    const kSecret  = '41575334774a616c725855746e46454d492f4b374d44454e472b62507852666943594558414d504c454b4559';
    const key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    const keyBytes = Buffer.from(`AWS4${key}`).toString('hex');
    expect(keyBytes).toEqual(kSecret);
  });

  test('Can derive key', () => {
    const key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
    const dateStamp = '20120215';
    const regionName = 'us-east-1';
    const serviceName = 'iam';

    const kDate    = '969fbb94feb542b71ede6f87fe4d5fa29c789342b0f407474670f0c2489e0a0d';
    const kRegion  = '69daa0209cd9c5ff5c8ced464a696fd4252e981430b10e3d3fd8e2f197d7a70c';
    const kService = 'f72cfd46f26bc4643f06a11eabb6c0ba18780c19a8da0c31ace671265e3c87fa';
    const kSigning = 'f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d';

    const dateKey = HAMC_SHA256(dateStamp, Buffer.from(`AWS4${key}`).toString('utf-8'));
    expect(dateKey.toString(Hex)).toEqual(kDate);
    const dateRegionKey = HAMC_SHA256(regionName, dateKey);
    expect(dateRegionKey.toString(Hex)).toEqual(kRegion);
    const dateRegionServiceKey = HAMC_SHA256(serviceName, dateRegionKey);
    expect(dateRegionServiceKey.toString(Hex)).toEqual(kService);
    const sig = HAMC_SHA256('aws4_request', dateRegionServiceKey);
    expect(sig.toString(Hex)).toEqual(kSigning);
  })
});
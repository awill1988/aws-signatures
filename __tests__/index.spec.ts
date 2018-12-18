import 'jest';
import {CanonicalRequest, urlPart, scope, sign, SigningKey, StringToSign, signedQuery, authHeader} from '../src';

jest.setTimeout(10000);

const AWSConfig = {
  Region: 'us-east-1',
};

const credentials = {
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
};

const mockRequest = {
  method: 'GET',
  uri: 'https://examplebucket.s3.amazonaws.com/test.txt',
  body: null,
  timestamp: 'Fri, 24 May 2013 00:00:00 GMT'
};

describe('AWS Signature v4', () => {
  test('Can extract host from full URI', () => {
    expect(urlPart(mockRequest.uri, 'domain'))
      .toBe('examplebucket.s3.amazonaws.com');
  });

  test('Creates Canonical Request', () => {
    const mock: any = {
      ...mockRequest
    };

    const request = new CanonicalRequest(
      'QUERY',
      mock.method as HTTPVerb,
      's3',
      scope(
        mock.timestamp,
        AWSConfig.Region,
        's3',
        {
          accessKeyId: credentials.accessKeyId,
          urlencode: true
        }
      ),
      '/test.txt',
      mock.query,
      {
        host: urlPart(mock.uri, 'domain'),
      },
      mock.timestamp,
      86400,
    );
    const cacanonicalRequest = request.toString();
    expect(cacanonicalRequest).toBe('GET\n' +
      '/test.txt\n' +
      'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\n' +
      'host:examplebucket.s3.amazonaws.com\n' +
      '\n' +
      'host\n' +
      'UNSIGNED-PAYLOAD');
  });

  test('Creates canonical request for Authorization Header', () => {

    const simulatedRequest = {
      method: 'GET',
      uri: 'https://examplebucket.s3.amazonaws.com/test.txt',
      body: null,
      timestamp: 'Fri, 24 May 2013 00:00:00 GMT'
    };

    const request = new CanonicalRequest(
      'HEADER',
      simulatedRequest.method as HTTPVerb,
      's3',
      scope(
        simulatedRequest.timestamp,
        AWSConfig.Region,
        's3',
        {
          accessKeyId: credentials.accessKeyId,
          urlencode: true
        }
      ),
      '/test.txt',
      {},
      {
        range: 'bytes=0-9',
        host: urlPart(simulatedRequest.uri, 'domain'),
      },
      simulatedRequest.timestamp,
      86400,
    );

    expect(request.toString())
      .toEqual('GET\n' +
        '/test.txt\n' +
        '\n' +
        'host:examplebucket.s3.amazonaws.com\n' +
        'range:bytes=0-9\n' +
        'x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n' +
        'x-amz-date:20130524T000000Z\n' +
        '\n' +
        'host;range;x-amz-content-sha256;x-amz-date\n' +
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

    const preSignedString = new StringToSign(
      credentials.accessKeyId,
      's3',
      AWSConfig.Region,
      simulatedRequest.timestamp,
      request,
    );

    const stringToSign = preSignedString.toString();

    expect(stringToSign).toEqual('AWS4-HMAC-SHA256\n' +
      '20130524T000000Z\n' +
      '20130524/us-east-1/s3/aws4_request\n' +
      '7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972');

    const key = SigningKey(
      credentials.secretAccessKey,
      simulatedRequest.timestamp,
      's3',
      AWSConfig.Region
    );

    const signature = sign(key,
      preSignedString.toString());

    expect(signature)
      .toBe('f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');

    const Authorization = authHeader(
      scope(
        simulatedRequest.timestamp,
        AWSConfig.Region,
        's3',
        {
          accessKeyId: credentials.accessKeyId,
          urlencode: true
        }
      ),
      request.signedHeaders(),
      signature
    );

    expect(Authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/'
      + 'aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature='
      + 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'
    );
  });

  test('Creates String To Sign', () => {

    const mock: any = {
      ...mockRequest
    };

    const request = new CanonicalRequest(
      'QUERY',
      mock.method as HTTPVerb,
      's3',
      scope(
        mock.timestamp,
        AWSConfig.Region,
        's3',
        {
          accessKeyId: credentials.accessKeyId,
          urlencode: true
        }
      ),
      '/test.txt',
      mock.query,
      {
        host: urlPart(mock.uri, 'domian'),
      },
      mock.timestamp,
      86400,
    );

    const preSignedString = new StringToSign(
      credentials.accessKeyId,
      's3',
      AWSConfig.Region,
      mock.timestamp,
      request,
    );
    const stringToSign = preSignedString.toString();

    expect(stringToSign).toBe('AWS4-HMAC-SHA256\n' +
      '20130524T000000Z\n' +
      '20130524/us-east-1/s3/aws4_request\n' +
      '3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04');
  });

  test('Can calculate signing key', () => {
    const mock: any = {
      ...mockRequest
    };

    const request = new CanonicalRequest(
      'QUERY',
      mock.method as HTTPVerb,
      's3',
      scope(
        mock.timestamp,
        AWSConfig.Region,
        's3',
        {
          accessKeyId: credentials.accessKeyId,
          urlencode: true
        }
      ),
      '/test.txt',
      mock.query,
      {
        host: urlPart(mock.uri, 'domain'),
      },
      mock.timestamp,
      86400,
    );

    const preSignedString = new StringToSign(
      credentials.accessKeyId,
      's3',
      AWSConfig.Region,
      mock.timestamp,
      request,
    );

    const key = SigningKey(
      credentials.secretAccessKey,
      mockRequest.timestamp,
      's3',
      AWSConfig.Region
    );

    const signature = sign(key,
      preSignedString.toString());

    expect(signature)
      .toBe('aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404')
  });

  test('Can generate presigned URL', () => {

    const url = 'https://examplebucket.s3.amazonaws.com/test.txt';
    const method = 'GET';
    const timestamp = mockRequest.timestamp;
    const ttl = 86400;

    const signedURL = signedQuery(
      'QUERY',
      credentials,
      {
        httpMethod: method,
        uri: url,
        service: 's3',
        region: AWSConfig.Region,
        timestamp,
        ttl,
      }
    );

    expect(signedURL.url)
      .toEqual('https://examplebucket.s3.amazonaws.com'
    + '/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential='
    + 'AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&'
    + 'X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&'
    + 'X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404');

  });
});

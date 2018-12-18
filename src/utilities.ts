import HAMC_SHA256 from 'crypto-js/hmac-sha256';
import SHA256 from 'crypto-js/sha256';
import Hex from 'crypto-js/enc-hex';
import {WordArray} from "crypto-js";

function zeroFill(n: number, w: number){
  const n_ = Math.abs(n);
  let zeros = Math.max(0, w - Math.floor(n_).toString().length );
  let zeroString = Math.pow(10,zeros).toString().substr(1);
  if( n < 0 ) {
    zeroString = '-' + zeroString;
  }
  return zeroString+n;
}

export function scope(
  timestamp: number|string,
  region: string,
  service: string,
  options?: {
    urlencode: boolean,
    accessKeyId: null|string
  }) {
  const date: Date = typeof timestamp === 'string'
    ? new Date(Date.parse(timestamp))
    : new Date(timestamp);
  const shouldEncode = options
    ? options.urlencode || false : false;
  const accessKey = options ? options.accessKeyId : undefined;
  const parts = [
    getDate(date),
    region,
    service,
    'aws4_request'
  ];
  if (accessKey) {
    parts.unshift(accessKey);
  }
  return shouldEncode
    ? encodeURI(parts.join('/'))
    : parts.join('/');
}

export function expires(ttl: number) {
  const now = new Date().getTime() / 1000;
  const then = now + ttl;
  return (then - now) < 86400 ? (then - now) : 86400;
}

export function urlPart(url: string, partName: string) {
  const regex = /^((http[s]?|ftp):\/)?\/?([^:\/\s]+)((\/\w+|\/)*\/)?([\w\-\.]+[^#?\s]+)?(.*)?(#[\w\-]+)?$/;
  const [
    all,
    ignore,
    scheme,
    domain,
    requestPath,
    lastPath,
    resource,
    queryString
  ]: RegExpMatchArray = url.match(regex) || [];
  switch (partName) {
    case 'domain':
      return domain;
    case 'scheme':
      return scheme;
    case 'path':
      return `${requestPath}${resource}`;
    case 'query':
      return queryString;
    default:
      break;
  }
  return domain;
}

export class CanonicalRequest {
  public readonly headers: IPairs;
  private readonly verb: HTTPVerb;
  private readonly resource: string;
  private readonly queryParams: IPairs;
  private readonly payload: any;
  private readonly service: string;
  private readonly authorizationType: string;
  private readonly timestamp: number;

  constructor(
    authorizationType: string,
    verb: HTTPVerb,
    service: string,
    // tslint:disable-next-line
    scope: string,
    resource: string = '',
    queryParams: IPairs = {},
    headers: IPairs = {},
    timestamp: string|number = new Date().getTime(),
    ttl?: number|null,
    payload?: any,
  ) {

    this.authorizationType = authorizationType;
    this.verb = verb.toUpperCase() as HTTPVerb;
    this.service = service;
    this.resource = resource || '';
    this.queryParams = queryParams;
    this.timestamp = typeof timestamp === 'string'
    ? new Date(timestamp).getTime() : timestamp;
    this.payload = payload;
    this.headers = headers;

    switch (this.authorizationType) {
      case 'QUERY':
        delete this.headers['X-Amz-SignedHeaders'];
        // Calculate TTL TODO Header Authentication
        if (!ttl) {
          delete this.queryParams['X-Amz-Expires'];
          this.queryParams['X-Amz-Expires'] = expires(86400).toString(10);
        } else {
          this.queryParams['X-Amz-Expires'] = expires(ttl).toString(10);
        }
        this.queryParams['X-Amz-Date'] = utcISO(timestamp);
        this.queryParams['X-Amz-SignedHeaders'] = this.signedHeaders(',');
        this.queryParams['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
        this.queryParams['X-Amz-Credential'] = scope;
        this.payload = 'UNSIGNED-PAYLOAD';
        break;
      case 'HEADER':
        delete this.queryParams['X-Amz-SignedHeaders'];
        this.headers = {
          ...this.headers,
        };
        this.headers['X-Amz-Date'] = utcISO(timestamp);
        this.headers['X-Amz-Content-Sha256'] = SHA256(payload || '').toString(Hex);
        break;
      default:
        break;
    }
  }

  httpVerb() {
    return this.verb.toUpperCase();
  }

  canonicalUri() {
    return this.resource;
  }

  canonicalHeaders() {
    return Object.keys(
      this.headers
    )
      .sort(((a, b) => {
        if (a.toLowerCase() < b.toLowerCase())
          return -1;
        if (a.toLowerCase() === b.toLowerCase())
          return 0;
        return 1;
      }))
      .map((key) => {
        return key.toLowerCase()
          + `:${this.headers[key]}\n`
      })
      .join('');
  }

  canonicalQueryString(signature?: string) {
    let result = Object.keys(this.queryParams).sort()
      .map((key: string) => {
        return encodeURIComponent(key)
          + '='
          + `${encodeURIComponent(this.queryParams[key]!)}`
      })
      .join('&');
    if (signature) {
      result = result.length
        ? `${result}&X-Amz-Signature=${signature}`
        : `X-Amz-Signature=${signature}`;
    }
    return result;
  }

  signedHeaders(separator = ';') {
    return Object.keys(
      this.headers
    )
      .sort(((a, b) => {
        if (a.toLowerCase() < b.toLowerCase())
          return -1;
        if (a.toLowerCase() === b.toLowerCase())
          return 0;
        return 1;
      }))
      .map((key) => key.toLowerCase())
      .join(separator);
  }

  signedPayload() {
    if (this.authorizationType === 'QUERY') {
      return 'UNSIGNED-PAYLOAD';
    }
    return SHA256(this.payload || '');
  }

  toString() {
    return [
      this.httpVerb(),
      this.canonicalUri(),
      this.canonicalQueryString(),
      this.canonicalHeaders(),
      this.signedHeaders(),
      this.signedPayload()
    ].join('\n');
  }
}

function toDate(date: number|Date|string) {
  let finalDate;
  switch (typeof date) {
    case 'string':
    case 'number':
      finalDate = new Date(date);
      break;
    default:
      finalDate = date;
      break;
  }
  return finalDate;
}

function utc(date: any) {
  let d = toDate(date);
  return Date.UTC(
    d.getUTCFullYear(),
    d.getUTCMonth(),
    d.getUTCDate(),
    d.getUTCHours(),
    d.getUTCMinutes(),
    d.getUTCSeconds()
  );
}

function utcISO(date: any) {
  let d = toDate(date);
  return [
    d.getUTCFullYear(),
    zeroFill(d.getUTCMonth() + 1, 2),
    zeroFill(d.getUTCDate(), 2),
    'T',
    zeroFill(d.getUTCHours(), 2),
    zeroFill(d.getUTCMinutes(), 2),
    zeroFill(d.getUTCSeconds(), 2),
    'Z'
  ].join('');
}

function getDate(date: any) {
  const finalDate = toDate(date);
  return [
    finalDate.getUTCFullYear(),
    zeroFill(finalDate.getUTCMonth() + 1, 2),
    zeroFill(finalDate.getUTCDate(), 2)
  ].join('');
}

export class StringToSign {
  private readonly timestamp: Date;
  private readonly accessKeyId: string;
  private readonly service: string;
  private readonly region: string;
  private readonly canonicalRequest: CanonicalRequest;
  constructor(
    accessKeyId: any,
    service: string,
    region: string,
    timestamp: string|Date = new Date(),
    canonicalRequest: CanonicalRequest
  ) {
    this.accessKeyId = accessKeyId;
    this.timestamp = typeof timestamp === 'string'
      ? new Date(timestamp) : timestamp;
    this.region = region;
    this.service = service;
    this.canonicalRequest = canonicalRequest;
  }

  hashedRequest() {
    const canonicalString = this.canonicalRequest.toString();
    const sha256 = SHA256(canonicalString);
    return sha256.toString(Hex);
  }

  toString() {
    return [
      'AWS4-HMAC-SHA256',
      utcISO(this.timestamp),
      scope(
        utc(this.timestamp),
        this.region,
        this.service
      ),
      this.hashedRequest()
    ].join('\n')
  }
}

export const SigningKey = (
  secret: string,
  timestamp: any,
  service: string,
  region: string
): WordArray => {
  const kDate = HAMC_SHA256(getDate(timestamp), `AWS4${secret}`);
  const kRegion = HAMC_SHA256(region, kDate);
  const kService = HAMC_SHA256(service, kRegion);
  return HAMC_SHA256('aws4_request', kService)
};

export function sign(secret: WordArray, content: string) {
  return HAMC_SHA256(content, secret)
    .toString(Hex);
}

export const signedQuery = (
  type: string = 'QUERY',
  credentials: {
    accessKeyId: string,
    secretAccessKey: string,
    sessionToken?: string,
  },
  {
    httpMethod,
    uri,
    service,
    region,
    timestamp,
    ttl,
  }: {
    httpMethod: string,
    uri: string,
    service: string,
    region: string,
    timestamp?: any,
    ttl?: string|number,
  }
) => {

  const host = urlPart(uri, 'domain');
  let resource = urlPart(uri, 'path');
  if (resource) {
    resource = resource.split('/')
      .map(e => encodeURIComponent(e))
      .join('/');
  }

  const query = urlPart(uri, 'query');

  const {
    accessKeyId,
    secretAccessKey,
    sessionToken,
  } = credentials;

  const queryParams = () => {
    if (!query && !sessionToken) {
      return {};
    }
    if (!query && type === 'QUERY') {
      return {
        'X-Amz-Security-Token': sessionToken
      };
    }
    const obj: any = {};
    query.slice(1).split('&')
      .forEach(q => {
        const [key, value] = q.split('=');
        obj[decodeURIComponent(key)] = decodeURIComponent(value);
      });
    if (sessionToken && type === 'QUERY') {
      obj['X-Amz-Security-Token'] = sessionToken;
    }
    return obj;
  };

  const headers: any = () => {
    if (!sessionToken || type === 'QUERY') {
      return {
        Host: host,
      };
    }
    return {
      Host: host,
      'X-Amz-Security-Token': sessionToken,
    }
  };

  const signingKey = SigningKey(
    secretAccessKey,
    timestamp,
    service,
    region
  );

  const credentialScope = scope(
    timestamp,
    region,
    service,
    {
      urlencode: false,
      accessKeyId,
    },
  );

  const request = new CanonicalRequest(
    type,
    httpMethod as HTTPVerb,
    service,
    credentialScope,
    resource,
    {
      ...queryParams(),
    },
    headers(),
    timestamp,
    typeof ttl === 'string' ? parseInt(ttl, 10): ttl,
  );

  const preSignedString = new StringToSign(
    credentials.accessKeyId,
    service,
    region,
    timestamp,
    request,
  );

  const signature = sign(
    signingKey,
    preSignedString.toString()
  );

  let qParameters = request.canonicalQueryString();

  if (type !== 'QUERY') {
    if (sessionToken) {
      request.headers['X-Amz-Security-Token'] = sessionToken;
    }
    request.headers['Authorization'] = authHeader(
      credentialScope,
      request.signedHeaders(),
      signature,
    );
  } else {
    qParameters = request.canonicalQueryString(signature);
  }

  return {
    url: `https://${host}${resource}?${qParameters}`,
    headers: request.headers,
  }
};

export function authHeader(scopedCredential: string, signedHeaders: string, signature: string) {
  return 'AWS4-HMAC-SHA256'
    + ` Credential=${scopedCredential}`
    + `,SignedHeaders=${signedHeaders}`
    + `,Signature=${signature}`;
}
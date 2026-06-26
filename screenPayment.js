"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");

const ALGORITHM = "AWS4-HMAC-SHA256";
const DEFAULT_CONTENT_TYPE = "application/json";

async function screenPayment(payment = {}, options = {}) {
  if (payment == null || typeof payment !== "object" || Array.isArray(payment)) {
    throw new TypeError("payment must be a JavaScript object");
  }

  const config = readConfig(options);
  const url = new URL(config.endpoint);
  const body = JSON.stringify(payment);
  const amzDate = toAmzDate(config.now || new Date());
  const dateStamp = amzDate.slice(0, 8);

  const headers = {
    SOAPAction: config.soapAction,
    "Content-Type": config.contentType,
    "X-Amz-Date": amzDate,
    Host: url.host,
  };

  if (config.sessionToken) {
    headers["X-Amz-Security-Token"] = config.sessionToken;
  }

  headers.Authorization = createAuthorizationHeader({
    method: config.method,
    url,
    headers,
    body,
    accessKeyId: config.accessKeyId,
    secretAccessKey: config.secretAccessKey,
    region: config.region,
    service: config.service,
    dateStamp,
    amzDate,
  });

  return request({
    url,
    method: config.method,
    headers,
    body,
    timeoutMs: config.timeoutMs,
  });
}

function readConfig(options) {
  const config = {
    endpoint: options.endpoint || process.env.PAYMENT_SCREEN_URL,
    method: (options.method || process.env.PAYMENT_SCREEN_METHOD || "POST").toUpperCase(),
    region: options.region || process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION,
    service: options.service || process.env.AWS_SERVICE || "execute-api",
    accessKeyId: options.accessKeyId || process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: options.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY,
    sessionToken: options.sessionToken || process.env.AWS_SESSION_TOKEN,
    soapAction: options.soapAction || process.env.SOAP_ACTION || "",
    contentType: options.contentType || process.env.PAYMENT_SCREEN_CONTENT_TYPE || DEFAULT_CONTENT_TYPE,
    timeoutMs: options.timeoutMs || 30000,
    now: options.now,
  };

  const missing = [];
  for (const key of ["endpoint", "region", "accessKeyId", "secretAccessKey"]) {
    if (!config[key]) {
      missing.push(key);
    }
  }

  if (missing.length) {
    throw new Error(`Missing required configuration: ${missing.join(", ")}`);
  }

  return config;
}

function createAuthorizationHeader(input) {
  const canonical = createCanonicalRequest({
    method: input.method,
    url: input.url,
    headers: input.headers,
    body: input.body,
  });
  const credentialScope = `${input.dateStamp}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = [
    ALGORITHM,
    input.amzDate,
    credentialScope,
    sha256Hex(canonical.canonicalRequest),
  ].join("\n");
  const signingKey = getSignatureKey(input.secretAccessKey, input.dateStamp, input.region, input.service);
  const signature = hmac(signingKey, stringToSign, "hex");

  return [
    `${ALGORITHM} Credential=${input.accessKeyId}/${credentialScope}`,
    `SignedHeaders=${canonical.signedHeaders}`,
    `Signature=${signature}`,
  ].join(", ");
}

function createCanonicalRequest({ method, url, headers, body }) {
  const canonicalUri = encodePath(url.pathname || "/");
  const canonicalQueryString = createCanonicalQueryString(url.searchParams);
  const canonicalHeaders = createCanonicalHeaders(headers);
  const payloadHash = sha256Hex(body || "");
  const canonicalRequest = [
    method.toUpperCase(),
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders.text,
    canonicalHeaders.signedHeaders,
    payloadHash,
  ].join("\n");

  return {
    canonicalRequest,
    signedHeaders: canonicalHeaders.signedHeaders,
  };
}

function createCanonicalHeaders(headers) {
  const normalized = Object.entries(headers)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([name, value]) => [
      name.toLowerCase(),
      String(value).trim().replace(/\s+/g, " "),
    ])
    .sort(([left], [right]) => left.localeCompare(right));

  return {
    text: normalized.map(([name, value]) => `${name}:${value}`).join("\n") + "\n",
    signedHeaders: normalized.map(([name]) => name).join(";"),
  };
}

function createCanonicalQueryString(searchParams) {
  const pairs = [];

  for (const [key, value] of searchParams) {
    pairs.push([awsEncode(key), awsEncode(value)]);
  }

  return pairs
    .sort(([leftKey, leftValue], [rightKey, rightValue]) => {
      if (leftKey === rightKey) {
        return leftValue.localeCompare(rightValue);
      }
      return leftKey.localeCompare(rightKey);
    })
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
}

function encodePath(pathname) {
  return pathname
    .split("/")
    .map((segment) => awsEncode(decodeURIComponent(segment)))
    .join("/");
}

function awsEncode(value) {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function getSignatureKey(secretAccessKey, dateStamp, regionName, serviceName) {
  const dateKey = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const dateRegionKey = hmac(dateKey, regionName);
  const dateRegionServiceKey = hmac(dateRegionKey, serviceName);
  return hmac(dateRegionServiceKey, "aws4_request");
}

function hmac(key, data, encoding) {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest(encoding);
}

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

function toAmzDate(date) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

function request({ url, method, headers, body, timeoutMs }) {
  const transport = url.protocol === "http:" ? http : https;

  return new Promise((resolve, reject) => {
    const req = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port,
        path: `${url.pathname}${url.search}`,
        method,
        headers: {
          ...headers,
          "Content-Length": Buffer.byteLength(body),
        },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks = [];

        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          const responseBody = Buffer.concat(chunks).toString("utf8");
          const parsedBody = parseResponseBody(responseBody, res.headers["content-type"]);
          const response = {
            statusCode: res.statusCode,
            headers: res.headers,
            body: parsedBody,
          };

          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(response);
          } else {
            const error = new Error(`Payment screening API returned HTTP ${res.statusCode}`);
            error.response = response;
            reject(error);
          }
        });
      },
    );

    req.on("timeout", () => req.destroy(new Error(`Payment screening API timed out after ${timeoutMs}ms`)));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

function parseResponseBody(body, contentType = "") {
  if (!body) {
    return null;
  }

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(body);
    } catch {
      return body;
    }
  }

  return body;
}

module.exports = {
  screenPayment,
  createAuthorizationHeader,
  createCanonicalRequest,
};

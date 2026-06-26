"use strict";

let crypto = require("node:crypto");
let https = require("node:https");

async function screenPayment(payment) {
  if (typeof payment !== "string") {
    throw new TypeError("payment must be a string");
  }

  let method = "POST";
  let endpoint = "https://example.execute-api.us-east-1.amazonaws.com/prod/screen";
  let region = "us-east-1";
  let service = "execute-api";
  let accessKeyId = "PUT_ACCESS_KEY_HERE";
  let secretAccessKey = "PUT_SECRET_KEY_HERE";
  let soapAction = "ScreenPayment";
  let contentType = "text/xml; charset=utf-8";

  let url = new URL(endpoint);
  let now = new Date();
  let amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  let dateStamp = amzDate.slice(0, 8);
  let body = payment;

  let headers = {
    SOAPAction: soapAction,
    "Content-Type": contentType,
    "X-Amz-Date": amzDate,
    Host: url.host,
  };

  headers.Authorization = createAuthorizationHeader(
    method,
    url,
    headers,
    body,
    accessKeyId,
    secretAccessKey,
    region,
    service,
    dateStamp,
    amzDate,
  );

  return sendRequest(method, url, headers, body);
}

function createAuthorizationHeader(
  method,
  url,
  headers,
  body,
  accessKeyId,
  secretAccessKey,
  region,
  service,
  dateStamp,
  amzDate,
) {
  let algorithm = "AWS4-HMAC-SHA256";
  let canonical = createCanonicalRequest(method, url, headers, body);
  let credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  let stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    sha256Hex(canonical.canonicalRequest),
  ].join("\n");
  let signingKey = getSignatureKey(secretAccessKey, dateStamp, region, service);
  let signature = hmac(signingKey, stringToSign, "hex");

  return `${algorithm} Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${canonical.signedHeaders}, Signature=${signature}`;
}

function createCanonicalRequest(method, url, headers, body) {
  let canonicalUri = encodePath(url.pathname || "/");
  let canonicalQueryString = createCanonicalQueryString(url.searchParams);
  let canonicalHeaders = createCanonicalHeaders(headers);
  let payloadHash = sha256Hex(body);
  let canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders.text,
    canonicalHeaders.signedHeaders,
    payloadHash,
  ].join("\n");

  return {
    canonicalRequest: canonicalRequest,
    signedHeaders: canonicalHeaders.signedHeaders,
  };
}

function createCanonicalHeaders(headers) {
  let normalized = Object.keys(headers)
    .map(function (name) {
      return [
        name.toLowerCase(),
        String(headers[name]).trim().replace(/\s+/g, " "),
      ];
    })
    .sort(function (left, right) {
      return left[0].localeCompare(right[0]);
    });

  let text = normalized
    .map(function (item) {
      return `${item[0]}:${item[1]}`;
    })
    .join("\n") + "\n";

  let signedHeaders = normalized
    .map(function (item) {
      return item[0];
    })
    .join(";");

  return {
    text: text,
    signedHeaders: signedHeaders,
  };
}

function createCanonicalQueryString(searchParams) {
  let pairs = [];

  for (let pair of searchParams) {
    pairs.push([awsEncode(pair[0]), awsEncode(pair[1])]);
  }

  return pairs
    .sort(function (left, right) {
      if (left[0] === right[0]) {
        return left[1].localeCompare(right[1]);
      }
      return left[0].localeCompare(right[0]);
    })
    .map(function (pair) {
      return `${pair[0]}=${pair[1]}`;
    })
    .join("&");
}

function encodePath(pathname) {
  return pathname
    .split("/")
    .map(function (part) {
      return awsEncode(decodeURIComponent(part));
    })
    .join("/");
}

function awsEncode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, function (char) {
    return `%${char.charCodeAt(0).toString(16).toUpperCase()}`;
  });
}

function getSignatureKey(secretAccessKey, dateStamp, region, service) {
  let dateKey = hmac(`AWS4${secretAccessKey}`, dateStamp);
  let dateRegionKey = hmac(dateKey, region);
  let dateRegionServiceKey = hmac(dateRegionKey, service);
  return hmac(dateRegionServiceKey, "aws4_request");
}

function hmac(key, value, encoding) {
  return crypto.createHmac("sha256", key).update(value, "utf8").digest(encoding);
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function sendRequest(method, url, headers, body) {
  return new Promise(function (resolve, reject) {
    let request = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method: method,
        headers: {
          SOAPAction: headers.SOAPAction,
          "Content-Type": headers["Content-Type"],
          "X-Amz-Date": headers["X-Amz-Date"],
          Authorization: headers.Authorization,
          Host: headers.Host,
          "Content-Length": Buffer.byteLength(body),
        },
      },
      function (response) {
        let chunks = [];

        response.on("data", function (chunk) {
          chunks.push(chunk);
        });

        response.on("end", function () {
          let responseBody = Buffer.concat(chunks).toString("utf8");

          resolve({
            statusCode: response.statusCode,
            headers: response.headers,
            body: responseBody,
          });
        });
      },
    );

    request.on("error", reject);
    request.write(body);
    request.end();
  });
}

module.exports = {
  screenPayment: screenPayment,
};

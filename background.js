var uploadQueue = new Map();

function encodeURIRFC3986(text) {
  // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent#encoding_for_rfc3986
  return encodeURIComponent(text).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function byte2hex(array) {
  return Array.from(array).map(b => b.toString(16).padStart(2, "0")).join("");
}

function byte2buffer(array) {
  return Uint8Array.from(array).buffer;
}


function string2byte(text) {
  return new TextEncoder().encode(text);
}

async function sha256(text) {
  const buffer = await crypto.subtle.digest("SHA-256", string2byte(text));
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256File(file) {
  const buffer = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(key, data){
  const k = (typeof key === 'string') ? string2byte(key) : byte2buffer(key);
  const m = (typeof data === 'string') ? string2byte(data) : byte2buffer(data);
  const c = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' },true, ['sign']);
  const s = await crypto.subtle.sign('HMAC', c, m);
  return Array.from(new Uint8Array(s))
}

async function signAwsV4(fields) {
  if (!fields) {
    throw new Error("AWS signing fields are required");
  }
  
  const { method, path, queryString, host, region, payloadHash, accessKey, secretKey, awsDate } = fields;
  
  if (!method || !path || !host || !region || !payloadHash || !accessKey || !secretKey || !awsDate) {
    throw new Error("Missing required AWS signing parameters");
  }
  
  try {
    const credential = `${awsDate.slice(0, 8)}/${region}/s3/aws4_request`;

    const signingRequest = [
      method.toUpperCase(),
      path,
      queryString || "",
      "host:" + host,
      "x-amz-content-sha256:" + payloadHash,
      "x-amz-date:" + awsDate,
      "",
      "host;x-amz-content-sha256;x-amz-date",
      payloadHash,
    ].join("\n");
    const signedRequest = await sha256(signingRequest);

    const signingString = [
      "AWS4-HMAC-SHA256",
      awsDate,
      credential,
      signedRequest,
    ].join("\n");
    
    const kDate = await hmacSha256("AWS4" + secretKey, awsDate.slice(0, 8));
    const kRegion = await hmacSha256(kDate, region);
    const kService = await hmacSha256(kRegion, "s3");
    const kSigning = await hmacSha256(kService, "aws4_request");
    const kSignature = await hmacSha256(kSigning, signingString);
    const signature = byte2hex(kSignature);

    return `AWS4-HMAC-SHA256 Credential=${accessKey}/${credential}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=${signature}`;
  } catch (error) {
    console.error(`AWS v4 signing failed: ${error.message}`);
    throw new Error(`AWS signature generation failed: ${error.message}`);
  }
}

function validateEndpoint(endpoint) {
  //Validate S3 endpoint to prevent SSRF attacks by blocking internal/private IP addresses.
  if (!endpoint || typeof endpoint !== 'string') {
    throw new Error('Invalid endpoint');
  }
  
  const blocked = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^169\.254\./
  ];
  
  if (blocked.some(pattern => pattern.test(endpoint))) {
    throw new Error('Internal endpoints not allowed');
  }
  
  return endpoint;
}

async function getAccount(accountId) {
  const accountInfo = await browser.storage.local.get(accountId);
  if (!accountInfo[accountId] || !("endpoint" in accountInfo[accountId])) {
    throw new Error("ERR_ACCOUNT_NOT_FOUND");
  }
  return accountInfo[accountId];
}

function getAccountEndpoint(account) {
  validateEndpoint(account.endpoint);
  return `${account.bucket}.${account.endpoint}`
}

function getAccountPrefix(account) {
  let prefix = account.prefix;
  if (prefix.endsWith("/")) { prefix = prefix.slice(0, -1); }
  if (prefix.startsWith("/")) { prefix = prefix.slice(1); }
  return prefix;
}

function awsDateNow() {
  return new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
}

async function uploadFile(account, upload, data) {
  try {
    const name = upload.name;
    const date = awsDateNow();
    const chunkSize = 5 * 1024 * 1024; // 5MB chunks
    
    if (data.size <= chunkSize) {
      const fileSha256 = await sha256File(data);
      const filePath = `${getAccountPrefix(account)}/${date}-SHA256-${fileSha256}/${encodeURIRFC3986(name)}`;
      return await uploadFileSingle(account, upload, data, filePath, fileSha256, date);
    }
    
    // For multipart uploads, use the SHA256 of the first chunk in the path
    // to avoid hashing the entire file. Each chunk is still hashed for signing.
    const firstChunk = data.slice(0, Math.min(chunkSize, data.size));
    const firstChunkHash = await sha256File(firstChunk);
    const filePath = `${getAccountPrefix(account)}/${date}-SHA256-${firstChunkHash}/${encodeURIRFC3986(name)}`;
    return await uploadFileMultipart(account, upload, data, filePath, chunkSize, date);
  } catch (error) {
    console.error(`Upload file failed: ${error.message}`);
    throw error;
  }
}

// Single file upload with retry logic
async function uploadFileSingle(account, upload, data, filePath, fileSha256, date) {
  const url = `https://${getAccountEndpoint(account)}/${filePath}`;

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const sign = await signAwsV4({
        method: "PUT",
        path: `/${filePath}`,
        queryString: "",
        host: getAccountEndpoint(account),
        region: account.region,
        accessKey: account.access_key,
        secretKey: account.secret_key,
        payloadHash: fileSha256,
        awsDate: date,
      });

      const response = await fetch(url, {
        method: "PUT",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-Amz-Date": date,
          "X-Amz-Content-SHA256": fileSha256,
          "Authorization": sign,
        },
        body: data,
        signal: upload.abortController.signal,
      });
      delete upload.abortController;
      return { response, url };
    } catch (e) {
      if (attempt === 3 || e.name === 'AbortError') {
        console.error(`Single file upload failed after ${attempt} attempts: ${e.message}`);
        throw new Error("ERR_UPLOAD_FAILED_NETWORK_ERROR");
      }
      // Exponential backoff: 1s, 2s, 3s delays
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
}

// Multipart upload: initiate -> upload parts -> complete
async function uploadFileMultipart(account, upload, data, filePath, chunkSize, date) {
  const rawUploadId = await initiateMultipartUpload(account, filePath, date);
  const uploadId = encodeURIRFC3986(rawUploadId);
  const parts = [];
  
  try {
    for (let i = 0; i < data.size; i += chunkSize) {
      const chunk = data.slice(i, Math.min(i + chunkSize, data.size));
      const partNumber = Math.floor(i / chunkSize) + 1;
      const etag = await uploadPart(account, filePath, uploadId, partNumber, chunk, upload.abortController.signal);
      parts.push({ PartNumber: partNumber, ETag: etag });
    }
    
    const response = await completeMultipartUpload(account, filePath, uploadId, parts);
    delete upload.abortController;
    const url = `https://${getAccountEndpoint(account)}/${filePath}`;
    return { response, url };
  } catch (e) {
    console.error(`Multipart upload failed: ${e.message}`, e);
    await abortMultipartUpload(account, filePath, uploadId);
    throw new Error("ERR_UPLOAD_FAILED_NETWORK_ERROR");
  }
}

// Start multipart upload, returns uploadId
async function initiateMultipartUpload(account, filePath, date) {
  const emptyHash = await sha256("");
  const sign = await signAwsV4({
    method: "POST",
    path: `/${filePath}`,
    queryString: "uploads=",
    host: getAccountEndpoint(account),
    region: account.region,
    accessKey: account.access_key,
    secretKey: account.secret_key,
    payloadHash: emptyHash,
    awsDate: date,
  });

  const response = await fetch(`https://${getAccountEndpoint(account)}/${filePath}?uploads`, {
    method: "POST",
    headers: {
      "X-Amz-Date": date,
      "X-Amz-Content-SHA256": emptyHash,
      "Authorization": sign,
    },
  });
  
  if (!response.ok) {
    const errorText = await response.text();
    console.error(`Initiate multipart failed: ${response.status}`, errorText);
    throw new Error(`Initiate failed: ${response.status}`);
  }

  const text = await response.text();
  const match = text.match(/<UploadId>([^<]+)<\/UploadId>/);
  if (!match) {
    throw new Error("No UploadId found in response");
  }
  return match[1];
}

// Upload single part with retry logic
async function uploadPart(account, filePath, uploadId, partNumber, chunk, signal) {
  const chunkHash = await sha256File(chunk);

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const partDate = awsDateNow();
      const sign = await signAwsV4({
        method: "PUT",
        path: `/${filePath}`,
        queryString: `partNumber=${partNumber}&uploadId=${uploadId}`,
        host: getAccountEndpoint(account),
        region: account.region,
        accessKey: account.access_key,
        secretKey: account.secret_key,
        payloadHash: chunkHash,
        awsDate: partDate,
      });

      const response = await fetch(`https://${getAccountEndpoint(account)}/${filePath}?partNumber=${partNumber}&uploadId=${uploadId}`, {
        method: "PUT",
        headers: {
          "X-Amz-Date": partDate,
          "X-Amz-Content-SHA256": chunkHash,
          "Authorization": sign,
        },
        body: chunk,
        signal,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      return response.headers.get("ETag");
    } catch (e) {
      if (attempt === 3 || e.name === 'AbortError') {
        console.error(`Upload part ${partNumber} failed after ${attempt} attempts: ${e.message}`);
        throw new Error(`Part ${partNumber} failed: ${e.message}`);
      }
      // Exponential backoff: 1s, 2s, 3s delays
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
}

// Finalize multipart upload with retry logic
async function completeMultipartUpload(account, filePath, uploadId, parts) {
  const body = `<CompleteMultipartUpload>${parts.map(p => `<Part><PartNumber>${p.PartNumber}</PartNumber><ETag>${p.ETag}</ETag></Part>`).join("")}</CompleteMultipartUpload>`;
  const bodyHash = await sha256(body);
  
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const completeDate = awsDateNow();
      const sign = await signAwsV4({
        method: "POST",
        path: `/${filePath}`,
        queryString: `uploadId=${uploadId}`,
        host: getAccountEndpoint(account),
        region: account.region,
        accessKey: account.access_key,
        secretKey: account.secret_key,
        payloadHash: bodyHash,
        awsDate: completeDate,
      });

      const response = await fetch(`https://${getAccountEndpoint(account)}/${filePath}?uploadId=${uploadId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/xml",
          "X-Amz-Date": completeDate,
          "X-Amz-Content-SHA256": bodyHash,
          "Authorization": sign,
        },
        body,
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      return response;
    } catch (e) {
      if (attempt === 3) {
        console.error(`Complete multipart failed after ${attempt} attempts: ${e.message}`);
        throw new Error(`Complete failed: ${e.message}`);
      }
      // Exponential backoff: 1s, 2s, 3s delays
      await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
    }
  }
}

// Cancel multipart upload on failure
async function abortMultipartUpload(account, filePath, uploadId) {
  try {
    const emptyHash = await sha256("");
    const abortDate = awsDateNow();
    const sign = await signAwsV4({
      method: "DELETE",
      path: `/${filePath}`,
      queryString: `uploadId=${uploadId}`,
      host: getAccountEndpoint(account),
      region: account.region,
      accessKey: account.access_key,
      secretKey: account.secret_key,
      payloadHash: emptyHash,
      awsDate: abortDate,
    });

    await fetch(`https://${getAccountEndpoint(account)}/${filePath}?uploadId=${uploadId}`, {
      method: "DELETE",
      headers: {
        "X-Amz-Date": abortDate,
        "X-Amz-Content-SHA256": emptyHash,
        "Authorization": sign,
      },
    });
  } catch (error) {
    console.error(`Abort multipart upload failed: ${error.message}`);
  }
}

browser.cloudFile.onFileUpload.addListener(async (account, { id, name, data }) => {
  const accountInfo = await getAccount(account.id);
  const upload = { id, name, abortController: new AbortController() };
  uploadQueue.set(id, upload);

    const { response, url } = await uploadFile(accountInfo, upload, data);
    if (response.status == 200) {
      console.log("upload success:", await response.text());
      return { url };
    }

    if (response.status) {
      console.log(await response.text());
      throw new Error(`ERR_UPLOAD_FAILED_HTTP_${response.status}`);
    }

    throw new Error("ERR_UPLOAD_FAILED_UNKNOWN");
});

browser.cloudFile.onFileUploadAbort.addListener((_account, id) => {
  const upload = uploadQueue.get(id);
  if (upload && upload.abortController) {
    upload.abortController.abort();
  }
});

browser.cloudFile.getAllAccounts().then(async (accounts) => {
  const allAccounts = await browser.storage.local.get();
  for (let account of accounts) {
    await browser.cloudFile.updateAccount(account.id, {
      configured: account.id in allAccounts,
    });
  }
});

browser.cloudFile.onAccountDeleted.addListener((accountId) => {
  browser.storage.local.remove(accountId);
});
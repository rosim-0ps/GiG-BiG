/**
 * Secure Group Messaging Crypto Utilities
 * Uses Web Crypto API for E2EE
 */

export async function generateIdentityKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveKey", "deriveBits"]
  );
}

export async function exportPublicKey(key: CryptoKey) {
  const exported = await window.crypto.subtle.exportKey("spki", key);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

export async function importPublicKey(pem: string) {
  const binaryDerString = atob(pem);
  const binaryDer = new Uint8Array(binaryDerString.length);
  for (let i = 0; i < binaryDerString.length; i++) {
    binaryDer[i] = binaryDerString.charCodeAt(i);
  }
  return await window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    []
  );
}

export async function generateGroupKey() {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptGroupKey(groupKey: CryptoKey, recipientPublicKey: CryptoKey) {
  // In a real Signal implementation, we'd use a more complex KDF.
  // Here we use ECDH to derive a temporary wrapping key.
  const ephemeralKeyPair = await generateIdentityKeyPair();
  const sharedSecret = await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: recipientPublicKey,
    },
    ephemeralKeyPair.privateKey,
    {
      name: "AES-KW",
      length: 256,
    },
    true,
    ["wrapKey", "unwrapKey"]
  );

  const wrappedKey = await window.crypto.subtle.wrapKey(
    "raw",
    groupKey,
    sharedSecret,
    "AES-KW"
  );

  const ephemeralPublic = await exportPublicKey(ephemeralKeyPair.publicKey);
  
  return JSON.stringify({
    wrappedKey: btoa(String.fromCharCode(...new Uint8Array(wrappedKey))),
    ephemeralPublic
  });
}

export async function decryptGroupKey(wrappedDataJson: string, myPrivateKey: CryptoKey) {
  const { wrappedKey, ephemeralPublic } = JSON.parse(wrappedDataJson);
  const ephemeralPublicKey = await importPublicKey(ephemeralPublic);

  const sharedSecret = await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: ephemeralPublicKey,
    },
    myPrivateKey,
    {
      name: "AES-KW",
      length: 256,
    },
    true,
    ["wrapKey", "unwrapKey"]
  );

  const binaryWrappedKey = new Uint8Array(atob(wrappedKey).split("").map(c => c.charCodeAt(0)));
  
  return await window.crypto.subtle.unwrapKey(
    "raw",
    binaryWrappedKey,
    sharedSecret,
    "AES-KW",
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptMessage(text: string, groupKey: CryptoKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    groupKey,
    encoded
  );

  return {
    content: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv))
  };
}

export async function decryptMessage(encryptedContent: string, ivBase64: string, groupKey: CryptoKey) {
  const iv = new Uint8Array(atob(ivBase64).split("").map(c => c.charCodeAt(0)));
  const data = new Uint8Array(atob(encryptedContent).split("").map(c => c.charCodeAt(0)));

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    groupKey,
    data
  );

  return new TextDecoder().decode(decrypted);
}

export async function exportIdentityPrivateKey(key: CryptoKey) {
  const exported = await window.crypto.subtle.exportKey("pkcs8", key);
  return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

export async function importIdentityPrivateKey(base64: string) {
  const binary = new Uint8Array(atob(base64).split("").map(c => c.charCodeAt(0)));
  return await window.crypto.subtle.importKey(
    "pkcs8",
    binary,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveKey", "deriveBits"]
  );
}

export async function exportGroupKey(key: CryptoKey) {
    const exported = await window.crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(exported)));
}

export async function importGroupKey(base64Key: string) {
    const binaryKey = new Uint8Array(atob(base64Key).split("").map(c => c.charCodeAt(0)));
    return await window.crypto.subtle.importKey(
        "raw",
        binaryKey,
        "AES-GCM",
        true,
        ["encrypt", "decrypt"]
    );
}

export async function encryptGroupKeyWithSecret(groupKey: CryptoKey, secret: string) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const exportedGroupKey = await window.crypto.subtle.exportKey("raw", groupKey);
  
  // Derive a key from the secret string
  const encoder = new TextEncoder();
  const secretData = encoder.encode(secret);
  const hash = await window.crypto.subtle.digest("SHA-256", secretData);
  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    hash,
    "AES-GCM",
    false,
    ["encrypt"]
  );

  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    exportedGroupKey
  );

  return {
    encryptedKey: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv))
  };
}

export async function decryptGroupKeyWithSecret(encryptedKeyBase64: string, ivBase64: string, secret: string) {
  const iv = new Uint8Array(atob(ivBase64).split("").map(c => c.charCodeAt(0)));
  const data = new Uint8Array(atob(encryptedKeyBase64).split("").map(c => c.charCodeAt(0)));
  
  const encoder = new TextEncoder();
  const secretData = encoder.encode(secret);
  const hash = await window.crypto.subtle.digest("SHA-256", secretData);
  const aesKey = await window.crypto.subtle.importKey(
    "raw",
    hash,
    "AES-GCM",
    false,
    ["decrypt"]
  );

  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    aesKey,
    data
  );

  return await window.crypto.subtle.importKey(
    "raw",
    decrypted,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
}

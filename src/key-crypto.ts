/**
 * Secure key storage utilities for encrypting/decrypting DESFire keys
 * Uses AES-GCM with PBKDF2 key derivation from user password
 */

export interface EncryptedKeyStore {
  /** Base64-encoded encrypted data */
  data: string;
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded salt for PBKDF2 */
  salt: string;
  /** Number of PBKDF2 iterations */
  iterations: number;
  /** Version for future compatibility */
  version: 1;
}

export interface DesfireFile {
  fileNo: number;
  fileType: string;
  commSet: string;
  accessRights: string;
  fileSize: number;
  contentPath: string;
}

export interface DesfireKey {
  kid: number;
  keyHex: string;
  keyType: number | 'AES' | '3DES';
  keyVersion: number;
  configurationChangeable: true;
  freeCreateDelete: false;
  freeDirectoryList: true;
  allowChangeMasterKey: true;
  changeKeyAccessRights: number;
}

export interface DesfireApplication {
  aid: string;
  keys: Array<DesfireKey>;
  files: Array<DesfireFile>;
  personalized: boolean;
  keyCount: number;
}

export interface DesfireTokenSpec {
  piccMasterKey: DesfireKey;
  applications: Array<DesfireApplication>;
}

const PBKDF2_ITERATIONS = 600000; // OWASP recommended minimum for SHA-256
const SALT_LENGTH = 32;
const IV_LENGTH = 12; // 96 bits for AES-GCM

/**
 * Derives an AES-256 key from a password using PBKDF2
 */
async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export const getByPath = <T>(obj: T, path: string): unknown => {
  return path.split('.').reduce((acc, key) => {
    if (
      acc &&
      typeof acc === 'object' &&
      key in (acc as Record<string, unknown>)
    ) {
      return (acc as Record<string, unknown>)[key];
    }
    return undefined;
  }, obj as unknown);
};

/**
 * Encrypts a DESFire key store with a user password
 */
export async function encryptKeyStore(
  keyStore: DesfireTokenSpec,
  password: string,
): Promise<EncryptedKeyStore> {
  if (!password || password.length < 8) {
    throw new Error('Password must be at least 8 characters');
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);

  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(keyStore));

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data,
  );

  return {
    data: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer),
    salt: arrayBufferToBase64(salt.buffer),
    iterations: PBKDF2_ITERATIONS,
    version: 1,
  };
}

/**
 * Decrypts an encrypted key store with a user password
 */
export async function decryptKeyStore(
  encryptedStore: EncryptedKeyStore,
  password: string,
): Promise<DesfireTokenSpec> {
  const salt = base64ToArrayBuffer(encryptedStore.salt);
  const iv = base64ToArrayBuffer(encryptedStore.iv);
  const data = base64ToArrayBuffer(encryptedStore.data);

  const key = await deriveKey(
    password,
    new Uint8Array(salt),
    encryptedStore.iterations,
  );

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      key,
      data,
    );

    const decoder = new TextDecoder();
    return JSON.parse(decoder.decode(decrypted)) as DesfireTokenSpec;
  } catch {
    throw new Error('Decryption failed: incorrect password or corrupted data');
  }
}

/**
 * Re-encrypts a key store with a new password
 */
export async function changePassword(
  encryptedStore: EncryptedKeyStore,
  oldPassword: string,
  newPassword: string,
): Promise<EncryptedKeyStore> {
  const keyStore = await decryptKeyStore(encryptedStore, oldPassword);
  return encryptKeyStore(keyStore, newPassword);
}

/**
 * Creates a new empty key store
 */
export function createKeyStore(): DesfireTokenSpec {
  return {
    piccMasterKey: {
      kid: 0,
      keyHex: '',
      keyType: 0,
      keyVersion: 0,
      configurationChangeable: true,
      freeCreateDelete: false,
      freeDirectoryList: true,
      allowChangeMasterKey: true,
      changeKeyAccessRights: 0,
    },
    applications: [],
  };
}

/**
 * Saves encrypted key store to localStorage
 */
export function saveToLocalStorage(
  encryptedStore: EncryptedKeyStore,
  storageKey = 'desfire-key-store',
): void {
  localStorage.setItem(storageKey, JSON.stringify(encryptedStore));
}

/**
 * Loads encrypted key store from localStorage
 */
export function loadFromLocalStorage(
  storageKey = 'desfire-key-store',
): EncryptedKeyStore | null {
  const data = localStorage.getItem(storageKey);
  if (!data) return null;
  try {
    return JSON.parse(data) as EncryptedKeyStore;
  } catch {
    return null;
  }
}

/**
 * Exports encrypted key store as a downloadable JSON file
 */
export function exportToFile(
  encryptedStore: EncryptedKeyStore,
  filename = 'desfire-keys.enc.json',
): void {
  const blob = new Blob([JSON.stringify(encryptedStore, null, 2)], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Imports encrypted key store from a file
 */
export async function importFromFile(file: File): Promise<EncryptedKeyStore> {
  const text = await file.text();
  const data = JSON.parse(text) as EncryptedKeyStore;

  // Validate structure
  if (
    !data.data ||
    !data.iv ||
    !data.salt ||
    !data.iterations ||
    data.version !== 1
  ) {
    throw new Error('Invalid encrypted key store format');
  }

  return data;
}

/**
 * Converts a hex string to Uint8Array for use with the protocol
 */
export function hexToKeyBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').toUpperCase();
  if (clean.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Converts Uint8Array to hex string
 */
export function keyBytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
}

/**
 * Validates a DESFire key based on its type
 */
export function validateDesfireKey(keyHex: string, keyType: string): boolean {
  const clean = keyHex.replace(/\s+/g, '');
  const expectedLengths: Record<string, number> = {
    DES: 16, // 8 bytes = 16 hex chars
    '2K3DES': 32, // 16 bytes = 32 hex chars
    '3K3DES': 48, // 24 bytes = 48 hex chars
    AES128: 32, // 16 bytes = 32 hex chars
  };

  const expected = expectedLengths[keyType];
  if (!expected) {
    throw new Error(`Unknown key type: ${keyType}`);
  }

  if (clean.length !== expected) {
    return false;
  }

  return /^[0-9A-Fa-f]+$/.test(clean);
}

// Utility functions for base64 encoding/decoding
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

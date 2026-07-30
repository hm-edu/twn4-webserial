import { getByPath, hexToKeyBytes, type DesfireKey } from './key-crypto';

export type SimpleProtocolMode = 'ascii' | 'binary';

export interface SimpleProtocolOptions {
  baudRate?: number;
  mode?: SimpleProtocolMode;
  useCrc?: boolean;
  timeoutMs?: number;
  dataBits?: 7 | 8;
  stopBits?: 1 | 2;
  parity?: 'none' | 'even' | 'odd';
  flowControl?: 'none' | 'hardware';
}

// Status codes from TWN4 Simple Protocol specification (page 10)
export const StatusCode = {
  ERR_NONE: 0, // No error
  ERR_UNKNOWN_FUNCTION: 1, // Unknown function
  ERR_MISSING_PARAMETER: 2, // Missing parameter
  ERR_UNUSED_PARAMETERS: 3, // Unused parameters
  ERR_INVALID_FUNCTION: 4, // Invalid function
  ERR_PARSER: 5, // Parser error
} as const;

export type StatusCodeType = (typeof StatusCode)[keyof typeof StatusCode];

export const StatusCodeName: Record<StatusCodeType, string> = {
  [StatusCode.ERR_NONE]: 'No error',
  [StatusCode.ERR_UNKNOWN_FUNCTION]: 'Unknown function',
  [StatusCode.ERR_MISSING_PARAMETER]: 'Missing parameter',
  [StatusCode.ERR_UNUSED_PARAMETERS]: 'Unused parameters',
  [StatusCode.ERR_INVALID_FUNCTION]: 'Invalid function',
  [StatusCode.ERR_PARSER]: 'Parser error',
};

export interface DesfireWriteDataParams {
  cryptoEnv: number;
  fileNo: number;
  offset: number;
  data: Uint8Array;
  commSet: number;
}

export interface DesfireReadDataParams {
  cryptoEnv: number;
  fileNo: number;
  offset: number;
  length: number;
  commSet: number;
}
export interface CreateApplicationParams {
  cryptoEnv: number;
  aidBigEndian: number | string;
  changeKeyAccessRights: number;
  configurationChangeable: boolean;
  freeCreateDelete: boolean;
  freeDirectoryList: boolean;
  allowChangeMasterKey: boolean;
  numberOfKeys: number;
  keyType: number;
}

export class ProtocolError extends Error {
  constructor(
    public statusCode: StatusCodeType,
    public response: Uint8Array,
    message?: string,
  ) {
    super(
      message ??
        `Protocol error: ${StatusCodeName[statusCode] || `Unknown (0x${statusCode.toString(16).padStart(2, '0')})`}`,
    );
    this.name = 'ProtocolError';
  }
}

export class NoTagFoundError extends Error {
  constructor(message?: string) {
    super(message ?? 'No tag found');
    this.name = 'NoTagFoundError';
  }
}

export interface DesfireAuthParams {
  cryptoEnv: number;
  keyNo: number;
  key: Uint8Array;
  keyType: number | 'AES' | '3DES';
  mode: number;
}

export interface DesfireChangeKeySettingsParams {
  cryptoEnv: number;
  changeKeyAccessRights: number;
  configurationChangeable: boolean;
  freeCreateDelete: boolean;
  freeDirectoryList: boolean;
  allowChangeMasterKey: boolean;
  numberOfKeys: number;
  keyType: number;
}

export interface DesfireChangeKeyParams {
  cryptoEnv: number;
  keyNo: number;
  oldKey: Uint8Array;
  newKey: Uint8Array;
  keyVersion: number;
  changeKeyAccessRights: number;
  configurationChangeable: boolean;
  freeCreateDelete: boolean;
  freeDirectoryList: boolean;
  allowChangeMasterKey: boolean;
  numberOfKeys: number;
  keyType: number | 'AES' | '3DES';
}

export interface DesfireCreateStandardFileParams {
  cryptoEnv: number;
  fileNo: number;
  commSet: number;
  accessRights: number;
  fileSize: number;
}

// Tag type definitions (from TWN4 Simple Protocol DocRev26, Appendix A)
export const TagType = {
  // Low Frequency
  LF_EM4102: 0x40,
  LF_HITAG1S: 0x41,
  LF_HITAG2: 0x42,
  LF_EM4150: 0x43,
  LF_AT5555: 0x44,
  LF_ISOFDX: 0x45,
  LF_EM4026: 0x46,
  LF_HITAGU: 0x47,
  LF_EM4305: 0x48,
  LF_HIDPROX: 0x49,
  LF_TIRIS: 0x4a,
  LF_COTAG: 0x4b,
  LF_IOPROX: 0x4c,
  LF_INDITAG: 0x4d,
  LF_HONEYTAG: 0x4e,
  LF_AWID: 0x4f,
  LF_GPROX: 0x50,
  LF_PYRAMID: 0x51,
  LF_KERI: 0x52,
  LF_DEISTER: 0x53,
  LF_CARDAX: 0x54,
  LF_NEDAP: 0x55,
  LF_PAC: 0x56,
  LF_IDTECK: 0x57,
  LF_ULTRAPROX: 0x58,
  LF_ICT: 0x59,
  LF_ISONAS: 0x5a,
  // High Frequency
  HF_MIFARE: 0x80,
  HF_ISO14443B: 0x81,
  HF_ISO15693: 0x82,
  HF_LEGIC: 0x83,
  HF_HIDICLASS: 0x84,
  HF_FELICA: 0x85,
  HF_SRX: 0x86,
  HF_NFCP2P: 0x87,
  HF_BLE: 0x88,
  HF_TOPAZ: 0x89,
  HF_CTS: 0x8a,
  HF_BLELC: 0x8b,
} as const;

export class TwN4SimpleProtocol {
  private port: SerialPort | null = null;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private options: Required<SimpleProtocolOptions>;

  constructor(options: SimpleProtocolOptions = {}) {
    this.options = {
      baudRate: options.baudRate ?? 9600,
      mode: options.mode ?? 'ascii',
      useCrc: options.useCrc ?? false,
      timeoutMs: options.timeoutMs ?? 1500,
      dataBits: options.dataBits ?? 8,
      stopBits: options.stopBits ?? 1,
      parity: options.parity ?? 'none',
      flowControl: options.flowControl ?? 'none',
    };
  }

  get isConnected(): boolean {
    return !!this.port;
  }

  async connect(): Promise<void> {
    if (!('serial' in navigator)) {
      throw new Error('Web Serial API not supported in this browser.');
    }
    try {
      this.port = await navigator.serial.requestPort();
      await this.port.open({
        baudRate: this.options.baudRate,
        dataBits: this.options.dataBits,
        stopBits: this.options.stopBits,
        parity: this.options.parity,
        flowControl: this.options.flowControl,
      });
      this.writer = this.port.writable?.getWriter() ?? null;
      this.reader = this.port.readable?.getReader() ?? null;
      if (!this.writer || !this.reader) {
        await this.disconnect();
        throw new Error('Unable to open serial reader/writer.');
      }
    } catch (error) {
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    try {
      if (this.reader) {
        await this.reader.cancel();
        this.reader.releaseLock();
      }
      if (this.writer) {
        this.writer.releaseLock();
      }
      if (this.port) {
        await this.port.close();
      }
    } finally {
      this.reader = null;
      this.writer = null;
      this.port = null;
    }
  }

  async sendCommand(command: Uint8Array): Promise<Uint8Array> {
    const response = await this.exchangeCommand(command);
    return this.validateResponse(response);
  }

  private async exchangeCommand(command: Uint8Array): Promise<Uint8Array> {
    if (!this.reader || !this.writer) {
      throw new Error('Not connected.');
    }

    const payload = this.options.useCrc ? appendCrc(command) : command;
    try {
      if (this.options.mode === 'ascii') {
        const line = bytesToHex(payload) + '\r';
        await this.writer.write(new TextEncoder().encode(line));
        const responseLine = await this.readAsciiLine(this.options.timeoutMs);
        console.log('Received ASCII response:', responseLine);
        const response = hexToBytes(responseLine);
        return response;
      }

      const length = payload.length;
      const header = new Uint8Array([length & 0xff, (length >> 8) & 0xff]);
      const frame = new Uint8Array(header.length + payload.length);
      frame.set(header, 0);
      frame.set(payload, header.length);
      await this.writer.write(frame);
      const lengthBytes = await this.readExact(2, this.options.timeoutMs);
      const responseLength = lengthBytes[0] | (lengthBytes[1] << 8);
      const response = await this.readExact(
        responseLength,
        this.options.timeoutMs,
      );
      return response;
    } catch (error) {
      throw error;
    }
  }

  private validateResponse(response: Uint8Array): Uint8Array {
    if (response.length === 0) {
      throw new Error('Empty response received');
    }
    // Validate CRC if enabled
    if (this.options.useCrc) {
      if (response.length < 3) {
        throw new Error('Response too short to contain CRC');
      }
      const dataWithCrc = response;
      const data = dataWithCrc.slice(0, -2);
      const receivedCrc =
        dataWithCrc[dataWithCrc.length - 2] |
        (dataWithCrc[dataWithCrc.length - 1] << 8);
      const calculatedCrc = computeCrc(data);

      if (receivedCrc !== calculatedCrc) {
        throw new Error(
          `CRC mismatch: received 0x${receivedCrc.toString(16).padStart(4, '0')}, ` +
            `calculated 0x${calculatedCrc.toString(16).padStart(4, '0')}`,
        );
      }
      response = data;
    }

    // Check status code (first byte of response)
    const statusCode = response[0] as StatusCodeType;

    if (statusCode !== StatusCode.ERR_NONE) {
      throw new ProtocolError(statusCode, response);
    }

    // Return response payload (without status code)
    return response;
  }

  async getUsbType(): Promise<Uint8Array> {
    return this.sendHexCommand('0005');
  }

  async searchTag(maxIdBytes: number): Promise<{
    tagType: number;
    uid: Uint8Array;
  }> {
    const response = await this.sendCommand(
      new Uint8Array([0x05, 0x00, maxIdBytes]),
    );
    if (response.length < 2) {
      throw new Error('Invalid SearchTag response: expected at least 2 bytes');
    }
    const found = response[1] === 0x01;
    if (!found) {
      throw new NoTagFoundError();
    }
    const tagType = response[2];
    const uidBytes = response[4];
    const uid = response.slice(5, 5 + uidBytes);
    return { tagType, uid };
  }

  async setRfOff(): Promise<Uint8Array> {
    return this.sendCommand(new Uint8Array([0x05, 0x01]));
  }

  async setTagTypes(
    tagTypesLF: number,
    tagTypesHF: number,
  ): Promise<Uint8Array> {
    const lfBytes = numberToBytesLE(tagTypesLF, 4);
    const hfBytes = numberToBytesLE(tagTypesHF, 4);
    return this.sendCommand(
      new Uint8Array([0x05, 0x02, ...lfBytes, ...hfBytes]),
    );
  }

  async getTagTypes(): Promise<Uint8Array> {
    return this.sendCommand(new Uint8Array([0x05, 0x03]));
  }

  async getSupportedTagTypes(): Promise<Uint8Array> {
    return this.sendCommand(new Uint8Array([0x05, 0x04]));
  }

  async setMifareOnly(): Promise<Uint8Array> {
    // MIFARE is 0x80, mask = 1 << (0x80 & 0x1F) = 1 << 0 = 0x01
    // LF: 0x00000000, HF: 0x00000001 (little-endian)
    return this.setTagTypes(0x00000000, 0x00000001);
  }

  /**
   * Initialize crypto environment (API CRYPTO - Crypto_Init)
   * Command: [0E00][Byte: CryptoEnv][Byte: CryptoMode][Byte Array(Var): Key]
   */
  async cryptoInit(
    cryptoEnv: number,
    cryptoMode: number,
    key: Uint8Array,
  ): Promise<Uint8Array> {
    if (key.length === 0) {
      throw new Error('CryptoInit requires a non-empty key');
    }
    const cmd = new Uint8Array([
      0x0e,
      0x00,
      cryptoEnv & 0xff,
      cryptoMode & 0xff,
      key.length & 0xff,
      ...key,
    ]);
    return this.sendCommand(cmd);
  }

  async desfireGetApplicationIds(
    cryptoEnv: number,
    maxAids: number,
  ): Promise<Array<string>> {
    const response = await this.sendCommand(
      new Uint8Array([0x0f, 0x00, cryptoEnv & 0xff, maxAids & 0xff]),
    );
    if (response.length < 2) {
      throw new Error(
        'Invalid GetApplicationIds response: expected at least 2 bytes',
      );
    }
    if (response[1] === 0) {
      throw new Error(
        'GetApplicationIds response indicates no applications available',
      );
    }
    const count = response[2];
    const aid = [];
    for (let i = 0; i < count; i++) {
      const offset = 3 + i * 4;
      const data = response.slice(offset, offset + 4);
      aid.push(bytesToHex(data.reverse()));
    }
    return aid;
  }

  async desfireSelectApplication(
    cryptoEnv: number,
    aidBigEndian: number | string,
  ): Promise<boolean> {
    const aid =
      typeof aidBigEndian === 'number'
        ? numberToBytesBE(aidBigEndian, 4)
        : hexToBytes(padHexEven(aidBigEndian)).slice(-4);
    const aidLe = new Uint8Array([aid[3], aid[2], aid[1], aid[0]]);
    const cmd = new Uint8Array([0x0f, 0x03, cryptoEnv & 0xff, ...aidLe]);
    const response = await this.sendCommand(cmd);
    if (response.length < 2) {
      throw new Error(
        'Invalid SelectApplication response: expected at least 2 bytes',
      );
    }
    return response[1] === 0x01;
  }

  async desfireAuthenticate(params: DesfireAuthParams): Promise<boolean> {
    const keyLen = params.key.length & 0xff;
    let keyType = 0x00;
    if (typeof params.keyType === 'number') {
      keyType = params.keyType;
    } else if (params.keyType === 'AES') {
      keyType = 0x02;
    } else if (params.keyType === '3DES') {
      keyType = 0x00;
    }
    const cmd = new Uint8Array([
      0x0f,
      0x04,
      params.cryptoEnv & 0xff,
      params.keyNo & 0xff,
      keyLen,
      ...params.key,
      keyType & 0xff,
      params.mode & 0xff,
    ]);
    const response = await this.sendCommand(cmd);
    if (response.length < 2) {
      throw new Error(
        'Invalid Authenticate response: expected at least 2 bytes',
      );
    }
    if (response[1] === 0x01) {
      return true;
    }
    throw new Error('Authenticate failed');
  }

  async desfireGetUid(cryptoEnv: number, bufferSize: number): Promise<string> {
    const response = await this.sendCommand(
      new Uint8Array([0x0f, 0x16, cryptoEnv & 0xff, bufferSize & 0xff]),
    );
    if (response.length < 2) {
      throw new Error('Invalid GetUid response: expected at least 2 bytes');
    }
    if (response[1] === 0) {
      throw new Error('GetUid response indicates no UID available');
    }
    // the uid is the complete response starting from offset 2
    return bytesToHex(response.slice(2));
  }

  async desfireFormatTag(cryptoEnv: number): Promise<boolean> {
    const response = await this.sendCommand(
      new Uint8Array([0x0f, 0x0f, cryptoEnv & 0xff]),
    );
    if (response.length != 2) {
      throw new Error('Invalid FormatTag response: expected 2 bytes');
    }
    return response[1] === 0x01;
  }

  async desfireDisableFormatCard(cryptoEnv: number): Promise<Uint8Array> {
    return this.sendCommand(new Uint8Array([0x0f, 0x1b, cryptoEnv & 0xff]));
  }

  async desfireFreeMemory(cryptoEnv: number): Promise<number> {
    const response = await this.sendCommand(
      new Uint8Array([0x0f, 0x0f, cryptoEnv & 0xff]),
    );
    if (response.length < 4) {
      throw new Error('Invalid FreeMemory response: expected at least 4 bytes');
    }
    // Free mem is a Uint16 in little-endian at offset 2
    return response[2] | (response[3] << 8);
  }

  /**
   * Create a DESFire standard data file (FileType 0x00)
   * Command: [0F10][Byte: CryptoEnv][Byte: FileNo][Byte: FileType][Byte: CommSet]
   *          [UInt16: AccessRights][UInt32: FileSize] appending 0`s
   */
  async desfireCreateStandardFile(
    params: DesfireCreateStandardFileParams,
  ): Promise<boolean> {
    const accessRightsLe = numberToBytesLE(params.accessRights, 2);
    const fileSizeLe = numberToBytesLE(params.fileSize, 4);
    const baseCmd = new Uint8Array([
      0x0f,
      0x10,
      params.cryptoEnv & 0xff,
      params.fileNo & 0xff,
      0x00, // FileType: Standard data file
      params.commSet & 0xff,
      ...accessRightsLe,
      ...fileSizeLe,
    ]);

    const totalLength = 24;
    const padLength = Math.max(0, totalLength - baseCmd.length);
    const cmd =
      padLength > 0
        ? new Uint8Array([...baseCmd, ...new Uint8Array(padLength)])
        : baseCmd;

    const response = await this.sendCommand(cmd);
    if (response.length < 2) {
      throw new Error(
        'Invalid CreateStandardFile response: expected at least 2 bytes',
      );
    }
    return response[1] === 0x01;
  }

  async createApplication(params: CreateApplicationParams): Promise<boolean> {
    const aid =
      typeof params.aidBigEndian === 'number'
        ? numberToBytesBE(params.aidBigEndian, 4)
        : hexToBytes(padHexEven(params.aidBigEndian)).slice(-4);
    const aidLe = new Uint8Array([aid[3], aid[2], aid[1], aid[0]]);

    const rights =
      ((params.changeKeyAccessRights & 0x0f) << 4) |
      (params.configurationChangeable ? 0x08 : 0) |
      (params.freeCreateDelete ? 0x04 : 0) |
      (params.freeDirectoryList ? 0x02 : 0) |
      (params.allowChangeMasterKey ? 0x01 : 0);

    const numberOfKeysLe = numberToBytesLE(params.numberOfKeys, 4);
    const keyTypeLe = numberToBytesLE(params.keyType, 4);

    const cmd = new Uint8Array([
      0x0f,
      0x01,
      params.cryptoEnv & 0xff,
      ...aidLe,
      rights & 0xff,
      ...numberOfKeysLe,
      ...keyTypeLe,
    ]);
    const response = await this.sendCommand(cmd);
    if (response.length < 2) {
      throw new Error(
        'Invalid CreateApplication response: expected at least 2 bytes',
      );
    }
    return response[1] === 0x01;
  }

  async deleteApplication(
    cryptoEnv: number,
    aidBigEndian: number | string,
  ): Promise<boolean> {
    const aid =
      typeof aidBigEndian === 'number'
        ? numberToBytesBE(aidBigEndian, 4)
        : hexToBytes(padHexEven(aidBigEndian)).slice(-4);
    const aidLe = new Uint8Array([aid[3], aid[2], aid[1], aid[0]]);
    const cmd = new Uint8Array([0x0f, 0x02, cryptoEnv & 0xff, ...aidLe]);
    const response = await this.sendCommand(cmd);
    if (response.length < 2) {
      throw new Error(
        'Invalid DeleteApplication response: expected at least 2 bytes',
      );
    }
    return response[1] === 0x01;
  }

  async getFileIds(cryptoEnv: number, maxFileIds: number): Promise<Uint8Array> {
    const response = await this.sendCommand(
      new Uint8Array([0x0f, 0x06, cryptoEnv & 0xff, maxFileIds & 0xff]),
    );
    if (response.length < 2) {
      throw new Error('Invalid GetFileIds response: expected at least 2 bytes');
    }
    if (response[1] === 0) {
      throw new Error('GetFileIds response indicates no files available');
    }
    return response.slice(2);
  }

  async desfireGetKeySettings(cryptoEnv: number): Promise<{
    keySettings: number;
    numOfKeys: number;
    keyType: number;
    changeKeyAccessRights: number;
    configurationChangeable: boolean;
    freeCreateDelete: boolean;
    freeDirectoryList: boolean;
    allowChangeMasterKey: boolean;
  }> {
    const response = await this.sendCommand(
      new Uint8Array([0x0f, 0x05, cryptoEnv & 0xff]),
    );

    if (response.length < 4) {
      throw new Error(
        'Invalid GetKeySettings response: expected at least 4 bytes',
      );
    }

    const keySettings = response[1];
    const numOfKeys = response[2];
    const keyType = response[3];

    return {
      keySettings,
      numOfKeys,
      keyType,
      changeKeyAccessRights: (keySettings >> 4) & 0x0f,
      configurationChangeable: (keySettings & 0x08) !== 0,
      freeCreateDelete: (keySettings & 0x04) !== 0,
      freeDirectoryList: (keySettings & 0x02) !== 0,
      allowChangeMasterKey: (keySettings & 0x01) !== 0,
    };
  }

  async desfireSetDefaultKey(
    cryptoEnv: number,
    key: Uint8Array,
    keyVersion: number,
  ): Promise<Uint8Array> {
    const keyLen = key.length & 0xff;
    const cmd = new Uint8Array([
      0x0f,
      0x1d,
      cryptoEnv & 0xff,
      keyLen,
      ...key,
      keyVersion & 0xff,
    ]);
    return this.sendCommand(cmd);
  }

  async desfireChangeKeySettings(
    params: DesfireChangeKeySettingsParams,
  ): Promise<Uint8Array> {
    const rights =
      ((params.changeKeyAccessRights & 0x0f) << 4) |
      (params.configurationChangeable ? 0x08 : 0) |
      (params.freeCreateDelete ? 0x04 : 0) |
      (params.freeDirectoryList ? 0x02 : 0) |
      (params.allowChangeMasterKey ? 0x01 : 0);

    const numberOfKeysLe = numberToBytesLE(params.numberOfKeys, 4);
    const keyTypeLe = numberToBytesLE(params.keyType, 4);

    const cmd = new Uint8Array([
      0x0f,
      0x18,
      params.cryptoEnv & 0xff,
      rights & 0xff,
      ...numberOfKeysLe,
      ...keyTypeLe,
    ]);
    return this.sendCommand(cmd);
  }

  async desfireChangeKey(params: DesfireChangeKeyParams): Promise<boolean> {
    const rights =
      ((params.changeKeyAccessRights & 0x0f) << 4) |
      (params.configurationChangeable ? 0x08 : 0) |
      (params.freeCreateDelete ? 0x04 : 0) |
      (params.freeDirectoryList ? 0x02 : 0) |
      (params.allowChangeMasterKey ? 0x01 : 0);

    const numberOfKeysLe = numberToBytesLE(params.numberOfKeys, 4);
    let keyTypeLe: Uint8Array = new Uint8Array(4);
    if (typeof params.keyType === 'number') {
      keyTypeLe = numberToBytesLE(params.keyType, 4);
    } else if (params.keyType === 'AES') {
      keyTypeLe = numberToBytesLE(0x02, 4);
    } else if (params.keyType === '3DES') {
      keyTypeLe = numberToBytesLE(0x00, 4);
    }

    const oldKeyLen = params.oldKey.length & 0xff;
    const newKeyLen = params.newKey.length & 0xff;
    const version = params.keyVersion & 0xff;
    const cmd = new Uint8Array([
      0x0f,
      0x19,
      params.cryptoEnv & 0xff,
      params.keyNo & 0xff,
      oldKeyLen,
      ...params.oldKey,
      newKeyLen,
      ...params.newKey,
      version,
      rights & 0xff,
      ...numberOfKeysLe,
      ...keyTypeLe,
    ]);
    const response = await this.sendCommand(cmd);
    return response.length >= 2 && response[1] === 0x01;
  }

  async sendHexCommand(hex: string): Promise<Uint8Array> {
    return this.sendCommand(hexToBytes(hex));
  }

  /**
   * Get the full response including status code (useful for debugging)
   */
  async sendCommandRaw(command: Uint8Array): Promise<Uint8Array> {
    return await this.exchangeCommand(command);
  }

  /**
   * Check if response indicates success without throwing
   */
  static isSuccessResponse(response: Uint8Array): boolean {
    return response.length >= 2 && response[1] === StatusCode.ERR_NONE;
  }

  /**
   * Get status code from response
   */
  static getStatusCode(response: Uint8Array): StatusCodeType | null {
    return response.length >= 2 ? (response[1] as StatusCodeType) : null;
  }

  /**
   * Get status message from response
   */
  static getStatusMessage(response: Uint8Array): string {
    const statusCode = TwN4SimpleProtocol.getStatusCode(response);
    if (statusCode === null) {
      return 'Invalid response';
    }
    return (
      StatusCodeName[statusCode] ||
      `Unknown status code: 0x${statusCode.toString(16).padStart(2, '0')}`
    );
  }

  private async readAsciiLine(timeoutMs: number): Promise<string> {
    const chunks: Array<number> = [];
    const start = Date.now();
    while (true) {
      if (Date.now() - start > timeoutMs)
        throw new Error('Timeout waiting for response');
      const { value, done } = await this.reader!.read();
      if (done) throw new Error('Port closed');
      if (!value) continue;
      for (const byte of value) {
        if (byte === 0x0d) {
          return new TextDecoder().decode(new Uint8Array(chunks));
        }
        chunks.push(byte);
      }
    }
  }

  private async readExact(
    count: number,
    timeoutMs: number,
  ): Promise<Uint8Array> {
    const chunks: Array<Uint8Array> = [];
    let total = 0;
    const start = Date.now();
    while (total < count) {
      if (Date.now() - start > timeoutMs)
        throw new Error('Timeout waiting for response');
      const { value, done } = await this.reader!.read();
      if (done) throw new Error('Port closed');
      if (!value) continue;
      chunks.push(value);
      total += value.length;
    }
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result.slice(0, count);
  }
  async tryPicc(key: string): Promise<boolean> {
    try {
      const app = await this.desfireSelectApplication(0x00, 0x000000);
      if (!app) {
        return false;
      }
      const auth = await this.desfireAuthenticate({
        cryptoEnv: 0x00,
        keyNo: 0x00,
        key: hexToKeyBytes(key),
        keyType: 0x00,
        mode: 0x01,
      });
      if (!auth) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }
  async isVanillaToken(): Promise<boolean> {
    return this.tryPicc('00000000000000000000000000000000');
  }

  /**
   * Beep with configurable volume, frequency and timing
   * Command: [0407][Byte: Volume][UInt16: Frequency][UInt16: OnTime][UInt16: OffTime]
   * @param volume  0-100 (0x00-0x64)
   * @param frequency  Frequency in Hz (little-endian UInt16)
   * @param onTimeMs  On duration in ms (little-endian UInt16)
   * @param offTimeMs  Off duration in ms (little-endian UInt16)
   */
  async beep(
    volume: number = 100,
    frequency: number = 2400,
    onTimeMs: number = 500,
    offTimeMs: number = 500,
  ): Promise<Uint8Array> {
    const freqLe = numberToBytesLE(frequency, 2);
    const onLe = numberToBytesLE(onTimeMs, 2);
    const offLe = numberToBytesLE(offTimeMs, 2);
    return this.sendCommand(
      new Uint8Array([0x04, 0x07, volume & 0xff, ...freqLe, ...onLe, ...offLe]),
    );
  }
  /**
   * Write data to a DESFire file (DESFire_WriteData)
   * Command: [0F09][Byte: CryptoEnv][Byte: FileNo][UInt16: Offset][Byte Array(Var): Data][Byte: CommSet]
   */
  async desfireWriteData(params: DesfireWriteDataParams): Promise<boolean> {
    const offsetLe = numberToBytesLE(params.offset, 2);
    const cmd = new Uint8Array([
      0x0f,
      0x09,
      params.cryptoEnv & 0xff,
      params.fileNo & 0xff,
      ...offsetLe,
      params.data.length & 0xff,
      ...params.data,
      params.commSet & 0xff,
    ]);
    const response = await this.sendCommand(cmd);
    if (response.length < 2) {
      throw new Error('Invalid WriteData response: expected at least 2 bytes');
    }
    return response[1] === 0x01;
  }

  /**
   * Read data from a DESFire file (DESFire_ReadData)
   * Command: [0F08][Byte: CryptoEnv][Byte: FileNo][UInt16: Offset][Byte: Length][Byte: CommSet]
   */
  async desfireReadData(params: DesfireReadDataParams): Promise<Uint8Array> {
    const offsetLe = numberToBytesLE(params.offset, 2);
    const cmd = new Uint8Array([
      0x0f,
      0x08,
      params.cryptoEnv & 0xff,
      params.fileNo & 0xff,
      ...offsetLe,
      params.length & 0xff,
      params.commSet & 0xff,
    ]);
    const response = await this.sendCommand(cmd);
    if (response.length < 2) {
      throw new Error('Invalid ReadData response: expected at least 2 bytes');
    }
    if (response[1] !== 0x01) {
      throw new Error('ReadData failed');
    }
    const lengthByte = response[2];
    if (response.length < 3 + lengthByte) {
      throw new Error('Invalid ReadData response: data length mismatch');
    }
    return response.slice(3, 3 + lengthByte);
  }
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').toUpperCase();
  if (clean.length % 2 !== 0)
    throw new Error('Hex string must have even length');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
}

export function padHexEven(hex: string): string {
  const clean = hex.replace(/\s+/g, '').toUpperCase();
  return clean.length % 2 === 0 ? clean : `0${clean}`;
}

export function numberToBytesBE(value: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = value & 0xff;
    value >>= 8;
  }
  return out;
}

export function numberToBytesLE(value: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = value & 0xff;
    value >>= 8;
  }
  return out;
}

export function updateCrc(crc: number, byte: number): number {
  byte ^= crc & 0xff;
  byte ^= (byte << 4) & 0xff;
  return (((byte << 8) | (crc >> 8)) ^ (byte >> 4) ^ (byte << 3)) & 0xffff;
}

export function computeCrc(bytes: Uint8Array): number {
  let crc = 0xffff;
  for (const b of bytes) crc = updateCrc(crc, b);
  return crc;
}

export function appendCrc(bytes: Uint8Array): Uint8Array {
  const crc = computeCrc(bytes);
  const withCrc = new Uint8Array(bytes.length + 2);
  withCrc.set(bytes, 0);
  withCrc[bytes.length] = crc & 0xff;
  withCrc[bytes.length + 1] = (crc >> 8) & 0xff;
  return withCrc;
}

type FieldSpec = {
  path: string;
  length: number;
  encoding: 'utf8';
  pad?: ' ' | '\0';
};
const encodeFixed = <T>(value: T, spec: FieldSpec): Uint8Array => {
  const padChar = spec.pad ?? '\0';
  const text = String(value ?? '');
  const bytes = new TextEncoder().encode(text);
  const out = new Uint8Array(spec.length);
  const fill = padChar === '\0' ? 0x00 : padChar.charCodeAt(0);
  out.fill(fill);
  out.set(bytes.slice(0, spec.length));
  return out;
};

export const baseKeySettings: DesfireKey = {
  kid: 0,
  keyHex: '00000000000000000000000000000000',
  keyType: '3DES',
  keyVersion: 0,
  configurationChangeable: true,
  freeCreateDelete: false,
  freeDirectoryList: true,
  allowChangeMasterKey: true,
  changeKeyAccessRights: 0x0000,
};
export const buildDesfireFileContent = <T>(
  source: T,
  fields: Array<FieldSpec>,
): Uint8Array => {
  const chunks = fields.map((field) =>
    encodeFixed(getByPath(source, field.path), field),
  );
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

export enum TokenState {
  Vanilla,
  HMToken,
  Unknown,
}

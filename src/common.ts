/********************************************************************************
 *   Ledger Node.js API
 *   (c) 2016-2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/
import type Transport from '@ledgerhq/hw-transport';

import bipPath from 'bip32-path';
import sha256 from 'fast-sha256';

export type GetPublicKeyResult = {
  publicKey: Uint8Array;
  address: Uint8Array | null;
};

export type GetWalletPublicKeyResult = {
  publicKey: string;
  address: string;
};

export type SignTransactionResult = {
  signature: Uint8Array;
};

export type GetVersionResult = {
  major: number;
  minor: number;
  patch: number;
};

/**
 * Common API for ledger apps
 *
 * @example
 * import Common from "hw-app-alamgu";
 * const alamgu = new Common(transport)
 */

export class Common {
  private _transport: Transport;
  private readonly _appName: string | null;
  private readonly _verbose: boolean | null;

  constructor({
    transport,
    scrambleKey = 'KDA',
    appName = 'Kadena',
    verbosity = false,
  }: {
    transport: Transport;
    scrambleKey?: string;
    appName?: string;
    verbosity?: boolean;
  }) {
    this._transport = transport;
    this._appName = appName;
    this._verbose = verbosity;
    transport.decorateAppAPIMethods(this, ['verifyAddress', 'getPublicKey', 'getWalletPublicKey', 'signTransaction', 'getVersion'], scrambleKey);
  }

  /**
   * Shows the address associated with a particular BIP32 path for verification,
   * and retrieves the public key and the address.
   *
   * @param path - the path to retrieve.
   */
  async verifyAddress(path: string): Promise<GetPublicKeyResult> {
    return this.getPublicKeyInternal(path, true);
  }

  /**
   * Retrieves the public key associated with a particular BIP32 path from the ledger app.
   *
   * @param path - the path to retrieve.
   */
  async getPublicKey(path: string): Promise<GetPublicKeyResult> {
    return this.getPublicKeyInternal(path, false);
  }

  /**
   * Retrieves the public key and address associated with a particular BIP32 path from the ledger app in human-readable form.
   * @param path
   */
  async getWalletPublicKey(path: string): Promise<GetWalletPublicKeyResult> {
    const internalPublicKey: GetPublicKeyResult = await this.getPublicKeyInternal(path, false);
    const publicKey: string = Buffer.from(internalPublicKey.publicKey).toString('hex');
    return {
      publicKey,
      address: `k:${publicKey}`,
    };
  }

  private async getPublicKeyInternal(path: string, do_prompt: boolean): Promise<GetPublicKeyResult> {
    const cla: number = 0x00;
    const ins: number = do_prompt ? 0x01 : 0x02;
    const p1: number = 0;
    const p2: number = 0;
    const payload: Buffer = buildBip32KeyPayload(path);
    const response: Buffer = await this.sendChunks(cla, ins, p1, p2, payload);
    const keySize: number = response[0];
    const publicKey: Buffer = response.subarray(1, keySize + 1); // slice uses end index.
    let address: Uint8Array | null = null;
    if (response.length > keySize + 2) {
      const addressSize: number = response[keySize + 1];
      address = response.subarray(keySize + 2, keySize + 2 + addressSize);
    }
    return {
      publicKey: publicKey,
      address: address,
    };
  }

  /**
   * Sign a transaction with the key at a BIP32 path.
   *
   * @param txn - The transaction; this can be any of a node Buffer, Uint8Array, or a hexadecimal string, encoding the form of the transaction appropriate for hashing and signing.
   * @param path - the path to use when signing the transaction.
   */
  async signTransaction(path: string, txn: string | Buffer | Uint8Array): Promise<SignTransactionResult> {
    const paths: number[] = splitPath(path);
    const cla: number = 0x00;
    const ins: number = 0x03;
    const p1: number = 0;
    const p2: number = 0;
    // Transaction payload is the byte length as uint32le followed by the bytes
    // Type guard not actually required but TypeScript can't tell that.
    if (this._verbose) this.log(txn);
    const rawTxn: Buffer = typeof txn == 'string' ? Buffer.from(txn, 'hex') : Buffer.from(txn);
    const hashSize: Buffer = Buffer.alloc(4);
    hashSize.writeUInt32LE(rawTxn.length, 0);
    // Bip32key payload same as getPublicKey
    const bip32KeyPayload: Buffer = buildBip32KeyPayload(path);
    // These are just squashed together
    const payload_txn: Buffer = Buffer.concat([hashSize, rawTxn]);
    this.log('Payload Txn', payload_txn);
    // TODO batch this since the payload length can be uint32le.max long
    const signature: Buffer = await this.sendChunks(cla, ins, p1, p2, [payload_txn, bip32KeyPayload]);
    return {
      signature,
    };
  }

  /**
   * Retrieve the app version on the attached ledger device.
   * @alpha TODO this doesn't exist yet
   */

  async getVersion(): Promise<GetVersionResult> {
    const [major, minor, patch] = await this.sendChunks(0x00, 0x00, 0x00, 0x00, Buffer.alloc(1));
    return {
      major,
      minor,
      patch,
    };
  }

  /**
   * Send a raw payload as chunks to a particular APDU instruction.
   *
   * @remarks
   *
   * This is intended to be used to implement a more useful API in this class and subclasses of it, not for end use.
   */
  async sendChunks(cla: number, ins: number, p1: number, p2: number, payload: Buffer | Buffer[]): Promise<Buffer> {
    let rv: Buffer = Buffer.alloc(0);
    let chunkSize: number = 230;
    if (payload instanceof Array) {
      payload = Buffer.concat(payload);
    }
    for (let i = 0; i < payload.length; i += chunkSize) {
      rv = await this._transport.send(cla, ins, p1, p2, payload.subarray(i, i + chunkSize));
    }
    // Remove the status code here instead of in signTransaction, because sendWithBlocks _has_ to handle it.
    return rv.subarray(0, -2);
  }

  /**
   * Convert a raw payload into what is essentially a singly-linked list of chunks, which
   allows the ledger to re-seek the data in a secure fashion.
   */
  async sendWithBlocks(
    cla: number,
    ins: number,
    p1: number,
    p2: number,
    payload: Buffer | Buffer[],
    // Constant (protocol dependent) data that the ledger may want to refer to
    // besides the payload.
    extraData: Map<String, Buffer> = new Map<String, Buffer>(),
  ): Promise<Buffer> {
    const chunkSize: number = 180;
    if (!(payload instanceof Array)) {
      payload = [payload];
    }
    let parameterList: Buffer[] = [];
    let data: Map<String, Buffer> = new Map<String, Buffer>(extraData);
    for (let j = 0; j < payload.length; j++) {
      let chunkList: Buffer[] = [];
      for (let i = 0; i < payload[j].length; i += chunkSize) {
        const cur: Buffer = payload[j].subarray(i, i + chunkSize);
        chunkList.push(cur);
      }
      // Store the hash that points to the "rest of the list of chunks"
      let lastHash: Buffer = Buffer.alloc(32);
      this.log(lastHash);
      // Since we are doing a foldr, we process the last chunk first
      // We have to do it this way, because a block knows the hash of
      // the next block.
      data = chunkList.reduceRight((blocks, chunk) => {
        const linkedChunk = Buffer.concat([lastHash, chunk]);
        this.log('Chunk: ', chunk);
        this.log('linkedChunk: ', linkedChunk);
        lastHash = Buffer.from(sha256(linkedChunk));
        blocks.set(lastHash.toString('hex'), linkedChunk);
        return blocks;
      }, data);
      parameterList.push(lastHash);
      lastHash = Buffer.alloc(32);
    }
    this.log(data);
    return await this.handleBlocksProtocol(cla, ins, p1, p2, Buffer.concat([Buffer.from([HostToLedger.START])].concat(parameterList)), data);
  }

  async handleBlocksProtocol(cla: number, ins: number, p1: number, p2: number, initialPayload: Buffer, data: Map<String, Buffer>): Promise<Buffer> {
    let payload: Buffer = initialPayload;
    let result: Buffer = Buffer.alloc(0);

    let rv_instruction: number;
    do {
      this.log('Sending payload to ledger: ', payload.toString('hex'));
      const rv: Buffer = await this._transport.send(cla, ins, p1, p2, payload);
      this.log('Received response: ', rv);
      rv_instruction = rv[0];
      const rv_payload: Buffer = rv.subarray(1, rv.length - 2); // Last two bytes are a return code.
      if (!(rv_instruction in LedgerToHost)) {
        throw new TypeError('Unknown instruction returned from ledger');
      }
      switch (rv_instruction) {
        case LedgerToHost.RESULT_ACCUMULATING:
        case LedgerToHost.RESULT_FINAL:
          result = Buffer.concat([result, rv_payload]);
          // Won't actually send this if we drop out of the loop for RESULT_FINAL
          payload = Buffer.from([HostToLedger.RESULT_ACCUMULATING_RESPONSE]);
          break;
        case LedgerToHost.GET_CHUNK:
          const chunk: Buffer | undefined = data.get(rv_payload.toString('hex'));
          this.log('Getting block ', rv_payload);
          this.log('Found block ', chunk);
          if (chunk) {
            payload = Buffer.concat([Buffer.from([HostToLedger.GET_CHUNK_RESPONSE_SUCCESS]), chunk]);
          } else {
            payload = Buffer.from([HostToLedger.GET_CHUNK_RESPONSE_FAILURE]);
          }
          break;
        case LedgerToHost.PUT_CHUNK:
          data.set(Buffer.from(sha256(rv_payload)).toString('hex'), rv_payload);
          payload = Buffer.from([HostToLedger.PUT_CHUNK_RESPONSE]);
          break;
      }
    } while (rv_instruction != LedgerToHost.RESULT_FINAL);
    return result;
  }

  log(...args: any[]): void {
    if (this._verbose) console.log(args);
  }
}

enum LedgerToHost {
  RESULT_ACCUMULATING = 0,
  RESULT_FINAL = 1,
  GET_CHUNK = 2,
  PUT_CHUNK = 3,
}

enum HostToLedger {
  START = 0,
  GET_CHUNK_RESPONSE_SUCCESS = 1,
  GET_CHUNK_RESPONSE_FAILURE = 2,
  PUT_CHUNK_RESPONSE = 3,
  RESULT_ACCUMULATING_RESPONSE = 4,
}

export const buildBip32KeyPayload = (path: string): Buffer => {
  const paths = splitPath(path);
  // Bip32Key payload is:
  // 1 byte with number of elements in u32 array path
  // Followed by the u32 array itself
  const payload = Buffer.alloc(1 + paths.length * 4);
  payload[0] = paths.length;
  paths.forEach((element: number, index: number): void => {
    payload.writeUInt32LE(element, 1 + 4 * index);
  });
  return payload;
};

export const splitPath = (path: string): number[] => {
  return bipPath.fromString(path).toPathArray();
};

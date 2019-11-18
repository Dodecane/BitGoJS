/**
 * @prettier
 */
import * as Bluebird from 'bluebird';
import * as crypto from 'crypto';
import { CoinFamily } from '@bitgo/statics';
const co = Bluebird.coroutine;
import * as bitgoAccountLib from '@bitgo/account-lib';
import { HDNode } from 'bitgo-utxo-lib';
import * as request from 'superagent';
import * as common from '../../common';

import { BaseCoin as StaticsBaseCoin } from '@bitgo/statics';

import {
  BaseCoin,
  KeyPair,
  ParsedTransaction,
  ParseTransactionOptions,
  SignedTransaction,
  SignTransactionOptions,
  VerifyAddressOptions,
  VerifyTransactionOptions,
  TransactionFee,
  TransactionRecipient as Recipient,
  TransactionPrebuild as BaseTransactionPrebuild,
  TransactionExplanation,
} from '../baseCoin';
import * as utxoLib from 'bitgo-utxo-lib';
import { BitGo } from '../../bitgo';
import { NodeCallback } from '../types';
import { TransactionBuilder } from '@bitgo/account-lib';

import debug = require('debug');
import {utxo} from "@bitgo/statics/dist/src/utxo";

export interface TronSignTransactionOptions extends SignTransactionOptions {
  txPrebuild: TransactionPrebuild;
  prv: string;
}

export interface TxInfo {
  recipients: Recipient[];
  from: string;
  txid: string;
}
export interface TronTransactionExplanation extends TransactionExplanation {
  expiration: number;
  timestamp: number;
}

export interface TransactionPrebuild extends BaseTransactionPrebuild {
  txHex: string;
  txInfo: TxInfo;
  feeInfo: TransactionFee;
}

export interface ExplainTransactionOptions {
  txHex?: string; // txHex is poorly named here; it is just a wrapped JSON object
  halfSigned?: {
    txHex: string; // txHex is poorly named here; it is just a wrapped JSON object
  };
  feeInfo: TransactionFee;
}

export interface RecoveryOptions {
  userKey: string; // Box A
  backupKey: string; // Box B
  bitgoKey: string; // Box C - this is bitgo's xpub and will be used to derive their root address
  recoveryDestination: string; // base58 address
  krsProvider?: string;
  walletPassphrase?: string;
}

export interface RecoveryTransaction {
  transaction: TransactionPrebuild;
  txid: string;
  recoveryAmount: number;
}

export enum NodeTypes {
  Full,
  Solidity,
}


export class Trx extends BaseCoin {
  protected readonly _staticsCoin: Readonly<StaticsBaseCoin>;

  constructor(bitgo: BitGo, staticsCoin?: Readonly<StaticsBaseCoin>) {
    super(bitgo);

    if (!staticsCoin) {
      throw new Error('missing required constructor parameter staticsCoin');
    }

    this._staticsCoin = staticsCoin;
  }

  getChain() {
    return this._staticsCoin.name;
  }

  getFamily(): CoinFamily {
    return this._staticsCoin.family;
  }

  getFullName() {
    return this._staticsCoin.fullName;
  }

  getBaseFactor() {
    return Math.pow(10, this._staticsCoin.decimalPlaces);
  }

  static createInstance(bitgo: BitGo, staticsCoin?: Readonly<StaticsBaseCoin>): BaseCoin {
    return new Trx(bitgo, staticsCoin);
  }

  /**
   * Flag for sending value of 0
   * @returns {boolean} True if okay to send 0 value, false otherwise
   */
  valuelessTransferAllowed(): boolean {
    return true;
  }

  /**
   * Checks if this is a valid base58 or hex address
   * @param address
   */
  isValidAddress(address: string): boolean {
    if (!address) {
      return false;
    }
    return this.isValidHexAddress(address) || bitgoAccountLib.Trx.Utils.isBase58Address(address);
  }

  /**
   * Checks if this is a valid hex address
   * @param address hex address
   */
  isValidHexAddress(address: string): boolean {
    return address.length === 42 && /^(0x)?([0-9a-f]{2})+$/i.test(address);
  }

  /**
   * Generate ed25519 key pair
   *
   * @param seed
   * @returns {Object} object with generated pub, prv
   */
  generateKeyPair(seed?: Buffer): KeyPair {
    // TODO: move this and address creation logic to account-lib
    if (!seed) {
      // An extended private key has both a normal 256 bit private key and a 256 bit chain code, both of which must be
      // random. 512 bits is therefore the maximum entropy and gives us maximum security against cracking.
      seed = crypto.randomBytes(512 / 8);
    }
    const hd = utxoLib.HDNode.fromSeedBuffer(seed);
    return {
      pub: hd.neutered().toBase58(),
      prv: hd.toBase58(),
    };
  }

  isValidXpub(xpub: string): boolean {
    try {
      return utxoLib.HDNode.fromBase58(xpub).isNeutered();
    } catch (e) {
      return false;
    }
  }

  isValidPub(pub: string): boolean {
    if (this.isValidXpub(pub)) {
      // xpubs can be converted into regular pubs, so technically it is a valid pub
      return true;
    }
    return new RegExp('^04[a-zA-Z0-9]{128}$').test(pub);
  }

  parseTransaction(
    params: ParseTransactionOptions,
    callback?: NodeCallback<ParsedTransaction>
  ): Bluebird<ParsedTransaction> {
    return Bluebird.resolve({}).asCallback(callback);
  }

  verifyAddress(params: VerifyAddressOptions): boolean {
    return true;
  }

  verifyTransaction(params: VerifyTransactionOptions, callback?: NodeCallback<boolean>): Bluebird<boolean> {
    return Bluebird.resolve(true).asCallback(callback);
  }

  signTransaction(params: TronSignTransactionOptions): SignedTransaction {
    const coinName = this.getChain();
    const txBuilder = new TransactionBuilder({ coinName });
    txBuilder.from(params.txPrebuild.txHex);

    let key = params.prv;
    if (this.isValidXprv(params.prv)) {
      key = HDNode.fromBase58(params.prv)
        .getKey()
        .getPrivateKeyBuffer();
    }

    txBuilder.sign({ key });
    const transaction = txBuilder.build();
    const response = {
      txHex: JSON.stringify(transaction.toJson()),
    };
    if (transaction.toJson().signature.length >= 2) {
      return response;
    }
    // Half signed transaction
    return {
      halfSigned: response,
    };
  }

  /**
   * Return boolean indicating whether input is valid seed for the coin
   *
   * @param prv - the prv to be checked
   */
  isValidXprv(prv: string): boolean {
    try {
      HDNode.fromBase58(prv);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Convert a message to string in hexadecimal format.
   *
   * @param message {Buffer|String} message to sign
   * @return the message as a hexadecimal string
   */
  toHexString(message: string | Buffer): string {
    if (typeof message === 'string') {
      return Buffer.from(message).toString('hex');
    } else if (Buffer.isBuffer(message)) {
      return message.toString('hex');
    } else {
      throw new Error('Invalid messaged passed to signMessage');
    }
  }

  /**
   * Sign message with private key
   *
   * @param key
   * @param message
   */
  signMessage(key: KeyPair, message: string | Buffer): Buffer {
    const toSign = this.toHexString(message);

    let prv = key.prv;
    if (this.isValidXprv(prv)) {
      prv = HDNode.fromBase58(prv)
        .getKey()
        .getPrivateKeyBuffer();
    }

    let sig = bitgoAccountLib.Trx.Utils.signString(toSign, prv, true);

    // remove the preceding 0x
    sig = sig.replace(/^0x/, '');

    return Buffer.from(sig, 'hex');
  }

  /**
   * Converts an xpub to a compressed pub
   * @param xpub
   */
  xpubToCompressedPub(xpub: string): string {
    if (!this.isValidXpub(xpub)) {
      throw new Error('invalid xpub');
    }

    const hdNode = utxoLib.HDNode.fromBase58(xpub, this.bitcoinEncoding());
    return hdNode.keyPair.__Q.getEncoded(false).toString('hex');
  }

  compressedPubToHexAddress(pub: string): string {
    const byteArrayAddr = bitgoAccountLib.Trx.Utils.getByteArrayFromHexAddress(pub);
    const rawAddress = bitgoAccountLib.Trx.Utils.getRawAddressFromPubKey(byteArrayAddr);
    return Buffer.from(rawAddress).toString('hex').toUpperCase();
  }

  xprvToCompressedPrv(xprv: string): string {
    if (!this.isValidXprv(xprv)) {
      throw new Error('invalid xprv');
    }

    const hdNode = utxoLib.HDNode.fromBase58(xprv, this.bitcoinEncoding());
    return hdNode.keyPair.d.toBuffer(32).toString('hex');
  };

  bitcoinEncoding(): any {
    return {
      messagePrefix: '\x18Bitcoin Signed Message:\n',
      bech32: 'bc',
      bip32: {
        public: 0x0488b21e,
        private: 0x0488ade4
      },
      pubKeyHash: 0x00,
      scriptHash: 0x05,
      wif: 0x80,
      coin: 'btc',
    };
  }

  /**
   * Make a query to Trongrid for information such as balance, token balance, solidity calls
   * @param query {Object} key-value pairs of parameters to append after /api
   * @param callback
   * @returns {Object} response from Trongrid
   */
  recoveryPost(query: { path: string, jsonObj: any, node: NodeTypes }, callback?: NodeCallback<any>): Bluebird<any> {
    const self = this;
    return co(function*() {
      let nodeUri = '';
      switch (query.node) {
        case NodeTypes.Full:
          nodeUri = common.Environments[self.bitgo.getEnv()].tronNodes.full;
          break;
        case NodeTypes.Solidity:
          nodeUri = common.Environments[self.bitgo.getEnv()].tronNodes.solidity;
          break;
        default:
          throw new Error('node type not found');
      }

      const response = yield request
          .post(nodeUri + query.path)
          .send(query.jsonObj);

      if (!response.ok) {
        throw new Error('could not reach Tron node');
      }
      return response.body;
    })
        .call(this)
        .asCallback(callback);
  }

  /**
   * Query our explorer for the balance of an address
   * @param address {String} the address encoded in hex
   * @param callback
   * @returns {BigNumber} address balance
   */
  getAccountBalanceFromNode(address: string, callback?: NodeCallback<any>): Bluebird<any> {
    const self = this;
    return co(function*() {
      const result = yield self.recoveryPost({
        path: '/walletsolidity/getaccount',
        jsonObj: { address },
        node: NodeTypes.Solidity,
      });
      return result.balance;
    })
      .call(this)
      .asCallback(callback);
  }

  /**
   * Retrieves our build transaction from a node.
   * @param toAddr hex-encoded address
   * @param fromAddr hex-encoded address
   * @param amount
   * @param callback
   */
  getBuildTransaction(toAddr: string, fromAddr: string, amount: number, callback?: NodeCallback<any>): Bluebird<any> {
    const self = this;
    return co(function*() {
      // our addresses should be base58, we'll have to encode to hex
      const result = yield self.recoveryPost({
        path: '/wallet/createtransaction',
        jsonObj: {
          to_address: toAddr,
          from_address: fromAddr,
          amount: amount.toFixed(0),
        },
        node: NodeTypes.Full,
      });
      return result.balance;
    })
        .call(this)
        .asCallback(callback);
  }

  /**
   * Builds a funds recovery transaction without BitGo.
   * We need to do three queries during this:
   * 1) Node query - how much money is in the account
   * 2) Build transaction - build our transaction for the amount
   * 3) Send signed build - send our signed build to a public node
   * @param params
   * @param callback
   */
  recover(params: RecoveryOptions, callback?: NodeCallback<RecoveryTransaction>): Bluebird<RecoveryTransaction> {
    const self = this;
    return co<RecoveryTransaction>(function*() {
      const isKrsRecovery = params.backupKey.startsWith('xpub') && !params.userKey.startsWith('xpub');
      const isUnsignedSweep = params.backupKey.startsWith('xpub') && params.userKey.startsWith('xpub');

      // get our user, backup keys
      const keys = yield self.initiateRecovery(params);

      // we need to decode our bitgoKey to a base58 address
      const bitgoAddress = self.compressedPubToHexAddress(self.xpubToCompressedPub(params.bitgoKey));
      const recoveryAddressHex = bitgoAccountLib.Trx.Utils.getHexAddressFromBase58Address(params.recoveryDestination);

      const recoveryAmount = yield self.getAccountBalanceFromNode(bitgoAddress);

      //const userPrv = HDKey.fromExtendedKey(keys[0]).privateKey;
      const userXPub = keys[0].neutered().toBase58();
      const userXPrv = keys[0].toBase58();
      const backupXPub = keys[1].neutered().toBase58();

      const userPrv = self.xprvToCompressedPrv(userXPrv);
      const userHexAddr = self.compressedPubToHexAddress(self.xpubToCompressedPub(userXPub));
      const backupHexAddr = self.compressedPubToHexAddress(self.xpubToCompressedPub(backupXPub));

      // TODO: some checks here about pubs being valid, for this wallet, etc.

      // construct the tx
      // TODO: recovery amount might not include fees, we'll have to figure out the max we can spend
      //   sensitive to energy and tx cost amounts
      // there's an assumption here being made about fees: for a wallet that hasn't been used in awhile, the implication is
      // it has maximum bandwidth. thus, a recovery should cost the minimum amount (1e6 sun)
      if (1e6 > recoveryAmount) {
        throw new Error('Amount of funds to recover wouldnt be able to fund a send');
      }
      const recoveryAmountMinusFees = recoveryAmount - 1e6;
      const buildTx = self.getBuildTransaction(recoveryAddressHex, bitgoAddress, recoveryAmountMinusFees);

      // construct our tx
      const txBuilder = new bitgoAccountLib.TransactionBuilder({ coinName: this.getChain() });
      txBuilder.from(buildTx);

      // this tx should be enough to drop into a node
      if (isUnsignedSweep) {
        return txBuilder.build().toJson();
      }

      // sign our tx
      txBuilder.sign({ key: userPrv });

      if (!isKrsRecovery) {
        const backupXPrv = keys[0].toBase58();
        const backupPrv = self.xprvToCompressedPrv(backupXPrv);

        txBuilder.sign({ key: backupPrv });
      }

      return txBuilder.build().toJson();
    })
      .call(this)
      .asCallback(callback);
  }

  /**
   * Explain a Tron transaction from txHex
   * @param params
   * @param callback
   */
  explainTransaction(
    params: ExplainTransactionOptions,
    callback?: NodeCallback<TronTransactionExplanation>
  ): Bluebird<TronTransactionExplanation> {
    return co<TronTransactionExplanation>(function*() {
      const txHex = params.txHex || (params.halfSigned && params.halfSigned.txHex);
      if (!txHex || !params.feeInfo) {
        throw new Error('missing explain tx parameters');
      }
      const coinName = this.getChain();
      const txBuilder = new TransactionBuilder({ coinName });
      txBuilder.from(txHex);
      const tx = txBuilder.build();
      const outputs = [
        {
          amount: tx.destinations[0].value.toString(),
          address: tx.destinations[0].address, // Should turn it into a readable format, aka base58
        },
      ];

      const displayOrder = [
        'id',
        'outputAmount',
        'changeAmount',
        'outputs',
        'changeOutputs',
        'fee',
        'timestamp',
        'expiration',
      ];

      const explanationResult: TronTransactionExplanation = {
        displayOrder,
        id: tx.id,
        outputs,
        outputAmount: outputs[0].amount,
        changeOutputs: [], // account based does not use change outputs
        changeAmount: '0', // account base does not make change
        fee: params.feeInfo,
        timestamp: tx.validFrom,
        expiration: tx.validTo,
      };

      return explanationResult;
    })
      .call(this)
      .asCallback(callback);
  }
}

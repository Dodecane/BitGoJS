import BigNumber from 'bignumber.js';
import { BaseCoin as CoinConfig } from '@bitgo/statics/dist/src/base';
import { DeployUtil, PublicKey } from 'casper-client-sdk';
import { parseInt } from 'lodash';
import { Deploy } from 'casper-client-sdk/dist/lib/DeployUtil';
import { BaseTransactionBuilder, TransactionType } from '../baseCoin';
import { BuildTransactionError, NotImplementedError, SigningError } from '../baseCoin/errors';
import { BaseAddress, BaseFee, BaseKey } from '../baseCoin/iface';
import { Transaction } from './transaction';
import { KeyPair } from './keyPair';
import { GasFee, CasperModuleBytesTransaction, CasperTransferTransaction, SignatureData, CasperNode } from './ifaces';
import { isValidPublicKey } from './utils';
import { SECP256K1_PREFIX, CHAIN_NAME } from './constants';

export const DEFAULT_M = 3;
export const DEFAULT_N = 2;
export abstract class TransactionBuilder extends BaseTransactionBuilder {
  private _source: BaseAddress;
  protected _fee: GasFee;
  private _transaction: Transaction;
  protected _session: CasperTransferTransaction | CasperModuleBytesTransaction;
  protected _duration: string;
  protected _multiSignerKeyPairs: KeyPair[];
  protected _signatures: SignatureData[];

  constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
    this.transaction = new Transaction(_coinConfig);
    this._multiSignerKeyPairs = [];
    this._signatures = [];
  }

  // region Base Builder
  /** @inheritdoc */
  protected async buildImplementation(): Promise<Transaction> {
    const gasPrice = this._fee.gasPrice ? parseInt(this._fee.gasPrice) : undefined;
    const deployParams = new DeployUtil.DeployParams(
      PublicKey.fromHex(SECP256K1_PREFIX + this._source.address),
      CHAIN_NAME,
      gasPrice,
    );

    let session;
    switch (this.transaction.type) {
      case TransactionType.Send:
        const transferSession = this._session as CasperTransferTransaction;
        session = new DeployUtil.Transfer(
          transferSession.amount,
          transferSession.target,
          undefined,
          transferSession.id,
        );
        break;
      case TransactionType.WalletInitialization:
        const moduleBytesSession = this._session as CasperModuleBytesTransaction;
        session = new DeployUtil.ModuleBytes(moduleBytesSession.moduleBytes, moduleBytesSession.args);
        break;
      default:
        throw new BuildTransactionError('Transaction Type error');
    }

    // @ts-ignore
    const payment = DeployUtil.standardPayment(parseInt(this._fee.gasLimit));

    const cTransaction = this.transaction.casperTx || DeployUtil.makeDeploy(deployParams, session, payment);
    this.transaction.casperTx = cTransaction;

    for (const kp of this._multiSignerKeyPairs) {
      await this.transaction.sign(kp);
    }
    for (const { signature } of this._signatures) {
      this.transaction.addSignature(signature);
    }
    return this.transaction;
  }

  /** @inheritdoc */
  protected fromImplementation(rawTransaction: DeployUtil.Deploy): Transaction {
    const tx = new Transaction(this._coinConfig);
    tx.casperTx = rawTransaction;
    this.initBuilder(tx);
    return this.transaction;
  }

  /** @inheritdoc */
  protected signImplementation(key: BaseKey): Transaction {
    this.checkDuplicatedKeys(key);
    const signer = new KeyPair({ prv: key.key });

    // Signing the transaction is an operation that relies on all the data being set,
    // so we set the source here and leave the actual signing for the build step
    this._multiSignerKeyPairs.push(signer);
    return this.transaction;
  }

  /**
   * Initialize the transaction builder fields using the decoded transaction data
   *
   * @param {Transaction} tx the transaction data
   */
  initBuilder(tx: Transaction): void {
    this.transaction = tx;
    this.transaction.loadPreviousSignatures();
    const txData = tx.toJson();
    this.fee({ gasLimit: txData.fee.toString() });
    this.source({ address: txData.from });
    // TODO: Instance optionals parameters or default parameters e.g startTime
    this.duration(txData.validDuration || '0'); // TODO: Replace '0' with the correct default value
  }

  // endregion

  // region Common builder methods

  /**
   * Set the transaction fees
   *
   * @param {BaseFee} fee The maximum gas to pay
   * @returns {TransactionBuilder} This transaction builder
   */
  fee(fee: GasFee): this {
    this.validateValue(new BigNumber(fee.gasLimit));
    this._fee = fee;
    return this;
  }

  /**
   * Set the transaction source
   *
   * @param {BaseAddress} address The source account
   * @returns {TransactionBuilder} This transaction builder
   */
  source(address: BaseAddress): this {
    this.validateAddress(address);
    this._source = address;
    return this;
  }

  /**
   * Set the transaction validDuration
   *
   * @param {string} validDuration The transaction validDuration
   * @returns {TransactionBuilder} This transaction builder
   */
  duration(validDuration: string): this {
    const duration = new BigNumber(validDuration);
    if (duration.isNaN()) {
      throw new BuildTransactionError('Invalid duration');
    }
    this.validateValue(duration);
    this._duration = duration.toString();
    return this;
  }

  /**
   * Set an external transaction signature
   *
   * @param signature Hex encoded signature string
   * @param keyPair The public key keypair that was used to create the signature
   * @returns This transaction builder
   */
  signature(signature: string, keyPair: KeyPair): this {
    // if we already have a signature for this key pair, just update it
    for (const oldSignature of this._signatures) {
      if (oldSignature.keyPair.getKeys().pub === keyPair.getKeys().pub) {
        oldSignature.signature = signature;
        return this;
      }
    }

    // otherwise add the new signature
    this._signatures.push({ signature, keyPair });
    return this;
  }

  // endregion

  // region Validators
  /** @inheritdoc */
  validateAddress(address: BaseAddress): void {
    if (!isValidPublicKey(address.address)) {
      throw new BuildTransactionError('Invalid address ' + address.address);
    }
  }

  /** @inheritdoc */
  validateKey(key: BaseKey): void {
    if (!new KeyPair({ prv: key.key })) {
      throw new BuildTransactionError('Invalid key');
    }
  }

  /** @inheritdoc */
  validateRawTransaction(rawTransaction: any): void {
    throw new NotImplementedError('validateRawTransaction not implemented');
    // if (!isValidRawTransactionFormat(rawTransaction)) {
    //   throw new ParseTransactionError('Invalid raw transaction');
    // }
  }

  /** @inheritdoc */
  validateTransaction(transaction?: Transaction): void {
    this.validateMandatoryFields();
  }

  /** @inheritdoc */
  validateValue(value: BigNumber): void {
    if (value.isLessThan(0)) {
      throw new BuildTransactionError('Value cannot be less than zero');
    }
  }

  validateMandatoryFields(): void {
    if (this._fee === undefined) {
      throw new BuildTransactionError('Invalid transaction: missing fee');
    }
    if (this._source === undefined) {
      throw new BuildTransactionError('Invalid transaction: missing source');
    }
  }

  /**
   * Validates that the given key is not already in this._multiSignerKeyPairs
   *
   * @param {BaseKey} key - The key to check
   */
  private checkDuplicatedKeys(key: BaseKey) {
    this._multiSignerKeyPairs.forEach(_sourceKeyPair => {
      if (_sourceKeyPair.getKeys().prv === key.key) {
        throw new SigningError('Repeated sign: ' + key.key);
      }
    });
  }

  // endregion

  /** @inheritdoc */
  protected get transaction(): Transaction {
    return this._transaction;
  }

  /** @inheritdoc */
  protected set transaction(transaction: Transaction) {
    this._transaction = transaction;
  }
}

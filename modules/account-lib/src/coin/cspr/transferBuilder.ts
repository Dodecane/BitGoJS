import { BaseCoin as CoinConfig } from '@bitgo/statics/dist/src/base';
import { PublicKey } from 'casper-client-sdk';
import { BuildTransactionError, SigningError } from '../baseCoin/errors';
import { BaseKey } from '../baseCoin/iface';
import { TransactionType } from '../baseCoin';
import { TransactionBuilder, DEFAULT_M } from './transactionBuilder';
import { Transaction } from './transaction';
import { SECP256K1_PREFIX } from './constants';

export class TransferBuilder extends TransactionBuilder {
  private _toAddress: string;
  private _amount: string;

  constructor(_coinConfig: Readonly<CoinConfig>) {
    super(_coinConfig);
  }

  /** @inheritdoc */
  protected async buildImplementation(): Promise<Transaction> {
    this._session = {
      amount: this._amount,
      target: PublicKey.fromHex(SECP256K1_PREFIX + this._toAddress),
    };
    this.transaction.setTransactionType(TransactionType.Send);
    return await super.buildImplementation();
  }

  /** @inheritdoc */
  initBuilder(tx: Transaction): void {
    super.initBuilder(tx);
    this.transaction.setTransactionType(TransactionType.Send);
    // TODO: init to and amount
  }

  /** @inheritdoc */
  protected signImplementation(key: BaseKey): Transaction {
    if (this._multiSignerKeyPairs.length >= DEFAULT_M) {
      throw new SigningError('A maximum of ' + DEFAULT_M + ' can sign the transaction.');
    }
    return super.signImplementation(key);
  }

  //region Transfer fields
  /**
   * Set the destination address where the funds will be sent,
   *
   * @param {string} address the address to transfer funds to
   * @returns {TransferBuilder} the builder with the new parameter set
   */
  to(address: string): this {
    // TODO : isValidAddress
    this._toAddress = address;
    return this;
  }

  /**
   * Set the amount to be transferred
   *
   * @param {string} amount amount to transfer
   * @returns {TransferBuilder} the builder with the new parameter set
   */
  amount(amount: string): this {
    // TODO : isValidAmount
    this._amount = amount;
    return this;
  }

  //endregion

  //region Validators
  validateMandatoryFields(): void {
    if (this._toAddress === undefined) {
      throw new BuildTransactionError('Invalid transaction: missing to');
    }
    if (this._amount === undefined) {
      throw new BuildTransactionError('Invalid transaction: missing amount');
    }
    super.validateMandatoryFields();
  }
  //endregion
}

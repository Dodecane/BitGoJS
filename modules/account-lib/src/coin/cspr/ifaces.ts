import { CLValue, PublicKey } from 'casper-client-sdk';
import { BigNumberish } from '@ethersproject/bignumber';
import { KeyPair } from '.';

export interface CasperTransaction {
  hash: string;
  from: string;
  data: string;
  fee: number;
  startTime?: string;
  validDuration?: string;
  to?: string;
  amount?: string;
}

export interface CasperNode {
  nodeUrl: string;
}

export interface SignatureData {
  signature: string;
  keyPair: KeyPair;
}

export interface GasFee {
  gasLimit: string;
  gasPrice?: string;
}

export interface CasperTransferTransaction {
  amount: BigNumberish;
  target: PublicKey;
  id?: number;
}

export interface CasperModuleBytesTransaction {
  moduleBytes: Uint8Array;
  args: Uint8Array;
}

export interface Owner {
  address: PublicKey;
  weight: number;
}

export type ContractArgs = Record<
  'action' | 'deployment_thereshold' | 'key_management_threshold' | 'accounts' | 'weights',
  CLValue
>;

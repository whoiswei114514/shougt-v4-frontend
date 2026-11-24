import type { BrowserPendingJob } from './browserCeremony';

export const BINDING_OID: string;
export const ALGORITHMS: string[];
export const CLIENT_SLOTS: string[];
export const CERT_SLOTS: string[];

export function encoded(object: { toBER(sizeOnly?: boolean): ArrayBuffer }): Uint8Array;
export function sha(value: Uint8Array | ArrayBuffer, name?: string): Promise<Uint8Array>;
export function certificateFromPem(pem: string): any;
export function caConstraints(certificate: any): { cA: boolean; pathLenConstraint?: number };
export function publicKeyInfo(der: Uint8Array): Promise<{ name: string; der: Uint8Array; parsed: any }>;
export function validatedCsr(job: BrowserPendingJob): Promise<{ parsed: any; der: Uint8Array; key: any }>;
export function validateInstallation(job: BrowserPendingJob & { chain_pem?: string[] }): Promise<{
  certificates: any[];
  leaf: any;
  chain: any[];
  key: any;
}>;
export function makeCertificate(
  job: BrowserPendingJob,
  ca: any,
  chain: any[],
  sign: (tbs: Uint8Array) => Promise<Uint8Array>,
): Promise<{ der: Uint8Array; pem: string; parsed: any }>;
export function buildChain(ca: any, job: BrowserPendingJob): Promise<any[]>;
export function fingerprint(certificate: any): Promise<string>;

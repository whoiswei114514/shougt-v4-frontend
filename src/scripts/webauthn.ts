import Axios from '../axios';
import { preferredSmartCard, preferSmartCard, smartCardCredential } from './smartcard';

type JsonOptions = {
  challenge_id: string;
  publicKey: Record<string, any>;
};

function decode(value: string): ArrayBuffer {
  const text = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(text, char => char.charCodeAt(0)).buffer;
}

function encode(value: ArrayBuffer): string {
  let text = '';
  for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function ensureSupported() {
  if (!window.isSecureContext || !window.PublicKeyCredential || !navigator.credentials) {
    throw new Error('请在 HTTPS 或 localhost 下使用支持通行密钥的浏览器');
  }
}

export function serializeCredential(credential: PublicKeyCredential) {
  const response = credential.response;
  const common = {
    id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  if (response instanceof AuthenticatorAttestationResponse) {
    return {...common, response: {
      clientDataJSON: encode(response.clientDataJSON), attestationObject: encode(response.attestationObject),
      transports: response.getTransports?.() || [],
    }};
  }
  const assertion = response as AuthenticatorAssertionResponse;
  return {...common, response: {
    clientDataJSON: encode(assertion.clientDataJSON), authenticatorData: encode(assertion.authenticatorData),
    signature: encode(assertion.signature), userHandle: assertion.userHandle ? encode(assertion.userHandle) : null,
  }};
}

export async function createCredential(options: JsonOptions, connection:'browser'|'smartcard'=preferredSmartCard()?'smartcard':'browser', rememberPreference=true) {
  if(connection==='smartcard')return {challenge_id:options.challenge_id,credential:await smartCardCredential('create',options.publicKey,rememberPreference)};
  if(rememberPreference)preferSmartCard(false);
  ensureSupported();
  const source = options.publicKey;
  const publicKey = {
    ...source, challenge: decode(source.challenge), user: {...source.user, id: decode(source.user.id)},
    excludeCredentials: source.excludeCredentials?.map((item: any) => ({...item, id: decode(item.id)})),
  } as PublicKeyCredentialCreationOptions;
  const credential = await navigator.credentials.create({publicKey}) as PublicKeyCredential | null;
  if (!credential) throw new Error('未完成密钥绑定');
  return {challenge_id: options.challenge_id, credential: serializeCredential(credential)};
}

export async function getAssertion(options: JsonOptions, connection:'browser'|'smartcard'=preferredSmartCard()?'smartcard':'browser', rememberPreference=true) {
  if(connection==='smartcard')return {challenge_id:options.challenge_id,credential:await smartCardCredential('get',options.publicKey,rememberPreference)};
  if(rememberPreference)preferSmartCard(false);
  ensureSupported();
  const source = options.publicKey;
  const publicKey = {...source, challenge: decode(source.challenge),
    allowCredentials: source.allowCredentials?.map((item: any) => ({...item, id: decode(item.id)})),
  } as PublicKeyCredentialRequestOptions;
  const credential = await navigator.credentials.get({publicKey}) as PublicKeyCredential | null;
  if (!credential) throw new Error('未完成安全密钥验证');
  return {challenge_id: options.challenge_id, credential: serializeCredential(credential)};
}

export async function reauthenticate() {
  const {data} = await Axios.post('/security/reauth-begin/');
  await Axios.post('/security/reauth-finish/', await getAssertion(data));
}

export function securityError(error: any): string {
  if (error?.name === 'NotAllowedError') return '验证已取消或超时，请重试';
  if (error?.name === 'InvalidStateError') return '此密钥可能已经绑定，请换一把密钥';
  return error?.response?.data?.msg || error?.message || '验证未完成';
}

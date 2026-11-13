// The Frameleaf account's sign-in in steps, as FrameleafAccount shows it: what `cloud_email_complete`
// answers, which screen follows, and the words for each second step.
import type { CloudAccount } from './server-types';

/** A second step this window can show. A Passkey is finished in the browser. */
export type SecondStep = 'totp' | 'recovery_code' | 'password';
export type StepMethod = 'email_code' | SecondStep;
/** `recovery`: Cloud says the person may have none of the offered methods to hand. */
export type Completed = { status: 'done'; account: CloudAccount } | { status: 'next'; methods: string[]; recovery?: boolean } | { status: 'browser'; recovery?: boolean };
/** Account recovery on the account site (Cloud's docs/app-sign-in.md), opened in the browser. */
export const recoveryUrl = 'https://frameleaf.cloud/recover';

const copy: Record<SecondStep, { title: string; sub: string; label: string; choose: string }> = {
  totp: { title: 'Two-Step Verification', sub: 'Enter the Verification Code from your authenticator app.', label: 'Verification Code', choose: 'Use My Authenticator App' },
  recovery_code: { title: 'Two-Step Verification', sub: 'Enter one of your Recovery Codes. Each one works once.', label: 'Recovery Code', choose: 'Use a Recovery Code' },
  password: { title: 'Enter your Password', sub: 'This account also needs its Frameleaf Password to finish.', label: 'Password', choose: 'Use My Password' },
};
export function secondStepCopy(method: SecondStep) { return copy[method]; }

/** The second steps to offer, Cloud's preferred one first. None: only the browser can finish (a Passkey). */
export function secondSteps(methods: readonly string[]): SecondStep[] {
  return methods.filter((method): method is SecondStep => Object.hasOwn(copy, method));
}

/** The screen after a proof Cloud accepted without finishing the sign-in. */
export function screenAfter(answer: Exclude<Completed, { status: 'done' }>): { mode: 'second'; methods: SecondStep[]; recovery: boolean } | { mode: 'browser'; recovery: boolean } {
  const methods = answer.status === 'next' ? secondSteps(answer.methods) : [];
  // Recovery is offered only when Cloud said so: after a Password it never is.
  const recovery = answer.recovery === true;
  return methods.length ? { mode: 'second', methods, recovery } : { mode: 'browser', recovery };
}

/** What a field keeps of what was typed: six digits for a Verification Code, no spaces in a Recovery Code. */
export function cleanProof(method: StepMethod, value: string): string {
  if (method === 'password') return value;
  if (method === 'recovery_code') return value.replace(/\s/g, '').slice(0, 64);
  return value.replace(/\D/g, '').slice(0, 6);
}
export function proofReady(method: StepMethod, value: string): boolean {
  if (method === 'password') return value.length > 0 && value.length <= 256;
  if (method === 'recovery_code') return value.length > 0;
  return /^\d{6}$/.test(value);
}

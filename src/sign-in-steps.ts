// The second step of a server sign-in, and the answer to "This needs Two-Step Verification": which
// proof the person is entering, what else would do, and the words for each. The code itself is
// never kept here; the transaction lives only as long as the step is on screen.
import { connectionError } from './errors.ts';

/** The proofs this app can enter. A Passkey is not one of them: Desktop has no WebAuthn. */
export type StepMethod = 'totp' | 'email_code' | 'recovery_code';
const enterable: readonly StepMethod[] = ['totp', 'email_code', 'recovery_code'];

/** What the server offered: `connect_server`'s "next" answer, or a `verification_required` refusal. */
export type StepOffer = { transaction: string; methods: string[]; sentTo?: string | null };
export type Step = {
  transaction: string;
  /** The offered proofs this app can enter, in the server's order (most preferred first). */
  methods: StepMethod[];
  /** The proof being entered; null when nothing offered can be entered here. */
  method: StepMethod | null;
  sentTo: string | null;
  /** The server offered a Passkey. */
  passkey: boolean;
  failure: string;
};

export function beginStep(offer: StepOffer): Step {
  const methods = [...new Set(offer.methods)].filter((method): method is StepMethod => enterable.includes(method as StepMethod));
  return { transaction: offer.transaction, methods, method: methods[0] ?? null, sentTo: offer.sentTo?.trim() || null, passkey: offer.methods.includes('passkey'), failure: '' };
}

/** Switch to another offered proof; a proof that was not offered changes nothing. */
export function chooseMethod(step: Step, method: StepMethod): Step {
  return step.methods.includes(method) ? { ...step, method, failure: '' } : step;
}

export function otherMethods(step: Step): StepMethod[] {
  return step.methods.filter(method => method !== step.method);
}

/** A refused proof keeps the step open, with the reason. */
export function stepFailed(step: Step, error: unknown): Step {
  return { ...step, failure: connectionError(error) };
}

/** Whether what was typed can be sent: six digits, or a Recovery Code of the server's length. */
export function proofReady(method: StepMethod | null, proof: string): boolean {
  const value = proof.trim();
  if (method === 'recovery_code') return value.length >= 1 && value.length <= 32;
  return method !== null && /^\d{6}$/.test(value);
}

export function stepPrompt(step: Step): string {
  switch (step.method) {
    case 'totp': return 'Enter the Verification Code from your authenticator app.';
    case 'email_code': return `Enter the Verification Code sent to ${step.sentTo ?? 'your email'}.`;
    case 'recovery_code': return 'Enter one of your Recovery Codes. Each one works once.';
    default: return step.passkey ? 'This needs a Passkey, and this app can’t use a Passkey yet.' : 'This needs a step this app can’t finish yet.';
  }
}

export function proofLabel(method: StepMethod | null): string {
  return method === 'recovery_code' ? 'Recovery Code' : 'Verification Code';
}

export function methodChoice(method: StepMethod): string {
  switch (method) {
    case 'totp': return 'Use Your Authenticator App';
    case 'email_code': return 'Use a Verification Code from Email';
    case 'recovery_code': return 'Use a Recovery Code';
  }
}

/** The offer inside a refused request that needs Two-Step Verification first, or null for any other error. */
export function verificationRequired(error: unknown): StepOffer | null {
  if (typeof error !== 'object' || error === null || (error as { code?: unknown }).code !== 'verification_required') return null;
  const { methods, transaction } = error as { methods?: unknown; transaction?: unknown };
  if (typeof transaction !== 'string' || !transaction) return null;
  return { transaction, methods: Array.isArray(methods) ? methods.filter((method): method is string => typeof method === 'string') : [] };
}

/** A request the server refused until Two-Step Verification, and how to run it again once verified. */
export type StepUpRequest = { offer: StepOffer; retry: () => void };
/** The Verify prompt of a page that loads in the background: the request it answers, or that it was dismissed. */
export type StepUpState = { request: StepUpRequest | null; dismissed: boolean };
export const noStepUp: StepUpState = { request: null, dismissed: false };
export const stepUpDismissed: StepUpState = { request: null, dismissed: true };

/**
 * The prompt after a background request failed. A refusal that needs Two-Step Verification opens it;
 * an open prompt is kept as it is (a later refusal carries a new transaction, and replacing the prompt
 * would discard what is being typed), and a dismissed one stays away until the page is loaded again.
 */
export function stepUpAfterFailure(state: StepUpState, error: unknown, retry: () => void): StepUpState {
  if (state.request || state.dismissed) return state;
  const offer = verificationRequired(error);
  return offer ? { request: { offer, retry }, dismissed: false } : state;
}

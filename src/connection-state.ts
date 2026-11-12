// What the window shows when restoring the saved server sign-in does not succeed.
import { savedSignInNeedsRecovery } from './errors.ts';

/**
 * - `reconnecting`: the server did not answer. The sign-in is kept and Frameleaf keeps trying.
 * - `needs-verification`: the server wants Two-Step Verification before this session continues.
 *   The sign-in and offline albums are kept; the step-up UI hooks in on this state.
 * - `locked`: the credential store needs unlocking before the sign-in can be read.
 * - `stale`: the sign-in was rejected or cannot be used, and has to be cleared before signing in again.
 */
export type SavedSignInState = 'reconnecting' | 'needs-verification' | 'locked' | 'stale';

export function savedSignInState(error: unknown): SavedSignInState {
  const code = error instanceof Error ? error.message : String(error);
  if (code === 'server_unreachable_or_certificate_invalid') return 'reconnecting';
  if (code === 'verification_required') return 'needs-verification';
  return savedSignInNeedsRecovery(code) ? 'locked' : 'stale';
}

export type SavedSignInView = {
  /** The sign-in form. Hidden while a saved sign-in is being kept, where signing in again would be refused. */
  signIn: boolean;
  /** The destructive "Clear saved sign-in" recovery, only for a sign-in that can no longer be used. */
  clearSavedSignIn: boolean;
  /** Frameleaf retries by itself, with backoff. */
  autoRetry: boolean;
  /** Shown in place of the sign-in form. */
  panel: { title: string; detail: string; retry: string } | null;
};

export function savedSignInView(state: SavedSignInState | null): SavedSignInView {
  switch (state) {
    case 'reconnecting':
      return {
        signIn: false, clearSavedSignIn: false, autoRetry: true,
        panel: {
          title: 'Reconnecting to your server…',
          detail: 'Your server isn’t answering right now. Your sign-in is saved on this computer, and Frameleaf keeps trying. AI processing and photo imports resume when it reconnects.',
          retry: 'Try now',
        },
      };
    case 'needs-verification':
      return {
        signIn: false, clearSavedSignIn: false, autoRetry: false,
        panel: {
          title: 'Two-Step Verification needed',
          detail: 'Your server needs Two-Step Verification before this computer can continue. Your sign-in and offline albums are kept.',
          retry: 'Check again',
        },
      };
    case 'stale':
      return { signIn: true, clearSavedSignIn: true, autoRetry: false, panel: null };
    default:
      return { signIn: true, clearSavedSignIn: false, autoRetry: false, panel: null };
  }
}

/** Seconds-scale backoff between reconnect attempts: 5 s doubling to a 5 minute ceiling. */
export function reconnectDelay(attempt: number): number {
  return Math.min(5_000 * 2 ** Math.min(Math.max(attempt, 0), 10), 300_000);
}

// What the window shows when restoring the saved server sign-in does not succeed.
import { savedSignInNeedsRecovery } from './errors.ts';
import { beginStep, type StepOffer } from './sign-in-steps.ts';

/**
 * - `reconnecting`: the server did not answer. The sign-in is kept and Frameleaf keeps trying.
 * - `needs-verification`: the server wants Two-Step Verification before this session continues.
 *   The sign-in and offline albums are kept, and the person verifies on that screen (`keptVerification`).
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
  /** The backend retries by itself, with backoff, also while the window is hidden. */
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

/**
 * How the Two-Step Verification screen lets the person carry on. `offer` is what the server asks
 * for (`saved_sign_in_verification`), null while it is not known; `asked` is whether that answer
 * has arrived. With a proof this app can enter, the person verifies on this screen. Otherwise the
 * only way on is to sign out and sign in again, and the screen says so and leads with Sign out.
 */
export function keptVerification(offer: StepOffer | null, asked: boolean): { verifyHere: boolean; signOutFirst: boolean; hint: string } {
  const verifyHere = !!offer && beginStep(offer).method !== null;
  const signOutFirst = asked && !verifyHere;
  // An offer with nothing to enter here is explained by the Verify prompt itself.
  return { verifyHere, signOutFirst, hint: asked && !offer ? 'To verify, sign out, then sign in again.' : '' };
}

/** What the backend's own reconnect attempt led to (the `connection-restored` event). */
export type Restored<Connection> = { connection: Connection | null; error: string | null };

// User-facing copy for the connection and cloud-account error codes the Rust side returns.
const messages: Record<string, string> = {
  local_host_active: 'Stop local management before connecting to another server.',
  worker_setup_unavailable: 'Your server could not authorize AI processing. Check its connection and permissions, then try Resume again.',
  worker_resume_offline: 'Your server did not answer. Check that it is online, then try Resume again.',
  worker_resume_awaiting_approval: 'An administrator on your server needs to approve this computer for AI processing.',
  worker_resume_unsupported_server: 'Your server does not accept AI processing from this computer. Update the server, then try Resume again.',
  // ponytail: these states drop the underlying error, so the copy covers both an interruption and a refusal.
  worker_resume_enrollment_failed: 'This computer could not register with your server. Try Resume again. If it keeps failing, remove this computer from the server’s Computers settings, then sign in again.',
  worker_resume_worker_setup_failed: 'This computer could not start or save an AI session with your server. Try Resume again. If it keeps failing, check that AI features are on for your account and that this computer’s credential store is unlocked.',
  worker_resume_credential_store_unavailable: 'Unlock your computer’s credential store, then try Resume again.',
  worker_resume_identity_changed: 'Your server’s identity changed. Sign out and sign in again to confirm it.',
  desktop_protocol_unsupported: 'Your server does not accept AI processing from this computer. Update the server, then try again.',
  server_identity_changed: 'Your server’s identity changed. Sign out and sign in again to confirm it.',
  network_client_unavailable: 'Frameleaf could not start its secure connection on this computer. Quit and reopen Frameleaf, then try again.',
  server_requires_https_origin: 'Enter your server’s address without a path or sign-in details. Use HTTPS unless the server is on your local network.',
  server_address_invalid: 'Enter a valid server address.',
  server_sign_in_retry_required: 'Your server’s identity could not be confirmed. Sign in again to continue.',
  server_identity_not_confirmed: 'Sign in again to confirm this server’s identity. Clear the saved sign-in first.',
  server_unreachable_or_certificate_invalid: 'Could not securely connect. Check the server address, network and certificate.',
  server_http_401: 'Sign-in expired or the email and password are incorrect. Sign out and try again.',
  server_http_403: 'Your server did not permit this sign-in.',
  credential_confirmation_unavailable: 'Your Mac could not confirm the saved sign-in. Restore it when the credential store is available.',
  credential_confirmation_changed: 'The stored sign-in changed. Restore the sign-in currently saved on this Mac.',
  credential_record_invalid: 'The saved sign-in could not be read. Clear it and sign in again.',
  credential_device_unlock_required: 'Your existing Frameleaf device key is locked. Retry this action and approve access on your Mac.',
  credential_unlock_required: 'Unlock your saved sign-in with Touch ID or your Mac password.',
  credential_store_locked_or_unavailable: 'Unlock your computer’s credential store, then try again.',
  credential_store_unavailable: 'The secure credential store is unavailable on this computer.',
  sign_out_before_switching_servers: 'Sign out before connecting to another server.',
  account_identity_changed: 'This session no longer matches the saved account. Sign out before continuing.',
  device_details_invalid: 'Enter a computer name between 1 and 128 characters.',
  admin_required: 'This page needs an administrator account on your server.',
  external_url_not_allowed: 'This link could not be opened in your browser.',
  discovery_unavailable: 'Servers on this network could not be searched. Enter the address instead.',
  // The browser's OAuth refusal arrives as cloud_sign_in_<error>; access_denied is the person cancelling.
  cloud_sign_in_access_denied: 'Frameleaf Cloud sign-in was cancelled.',
  cloud_sign_in_timed_out: 'Frameleaf Cloud sign-in timed out. Try again.',
  cloud_sign_in_failed: 'Frameleaf Cloud did not complete the sign-in. Try again.',
  cloud_unreachable: 'Frameleaf Cloud could not be reached. Check your connection and try again.',
  cloud_sign_in_required: 'Your Frameleaf Cloud session ended. Sign in again.',
  cloud_exchange_unsupported: 'This server does not accept Frameleaf Cloud sign-in yet. Sign in with its address, email and password.',
  cloud_server_unreachable: 'None of this server’s addresses answered. Check that it is online, or try again on its home network.',
  cloud_email_invalid: 'Enter a valid email address.',
  cloud_email_wrong_code: 'That code is incorrect. Check it and try again.',
  cloud_email_expired_code: 'That code expired. Request a new one to continue.',
  cloud_email_no_account: 'There’s no account for this email yet. Create an account to continue.',
  cloud_email_consent_changed: 'The terms or privacy notice changed. Review them again to continue.',
  cloud_email_rate_limited: 'Too many sign-ins in a short time. Try again in a few minutes.',
  cloud_email_signup_paused: 'Creating new accounts is paused for a moment. Try again later.',
  cloud_email_unverified: 'Confirm this account’s email address first, using the link Frameleaf sent you.',
  cloud_email_unavailable: 'Account sign-in is unavailable right now. Try again.',
  cloud_sign_out_before_switching_accounts: 'Sign out of the current Frameleaf account first.',
  server_oauth_cancelled: 'Sign-in was cancelled.',
  server_oauth_failed: 'The server didn’t complete that sign-in. Try again, or ask the person who runs it.',
  server_oauth_unavailable: 'This server’s single sign-on isn’t turned on.',
  cloud_server_address_unlisted: 'Your Frameleaf account doesn’t list this address for that server. Sign in with this server’s own login, or connect on its home network.',
  server_not_frameleaf: 'That address answered, but not as a Frameleaf server. Check the address.',
  wallet_step_up_required: 'Raising the cap or turning on auto-reload needs a fresh sign-in on frameleaf.cloud. Open your account settings to change it there.',
};
export function connectionError(error: unknown): string {
  const code = error instanceof Error ? error.message : typeof error === 'string' ? error : '';
  return Object.hasOwn(messages, code) ? messages[code]! : 'This operation could not finish. Check your connection and try again.';
}

export function savedSignInNeedsRecovery(error: unknown): boolean {
  return ['credential_unlock_required', 'credential_confirmation_unavailable', 'credential_confirmation_changed'].includes(String(error));
}

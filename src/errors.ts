// User-facing copy for the connection and cloud-account error codes the Rust side returns.
const messages: Record<string, string> = {
  local_host_active: 'Stop local management before connecting to another server.',
  worker_setup_unavailable: 'Your server could not authorize AI processing. Check its connection and permissions, then try Resume again.',
  server_requires_https_origin: 'Enter your server’s address without a path or sign-in details. Use HTTPS unless the server is on your local network.',
  server_address_invalid: 'Enter a valid server address.',
  server_sign_in_retry_required: 'Your server’s identity could not be confirmed. Sign in again to continue.',
  server_identity_not_confirmed: 'Sign in again to confirm this server’s identity. Clear the saved sign-in first.',
  server_unreachable_or_certificate_invalid: 'Could not securely connect. Check the server address, network and certificate.',
  server_http_401: 'Sign-in expired or the email and password are incorrect. Sign out and try again.',
  server_http_403: 'Your server did not permit this sign-in.',
  credential_unlock_required: 'Unlock your saved sign-in with Touch ID or your Mac password.',
  credential_store_locked_or_unavailable: 'Unlock your computer’s credential store, then try again.',
  credential_store_unavailable: 'The secure credential store is unavailable on this computer.',
  sign_out_before_switching_servers: 'Sign out before connecting to another server.',
  account_identity_changed: 'This session no longer matches the saved account. Sign out before continuing.',
  device_details_invalid: 'Enter a computer name between 1 and 128 characters.',
  admin_required: 'This page needs an administrator account on your server.',
  external_url_not_allowed: 'This link could not be opened in your browser.',
  discovery_unavailable: 'Servers on this network could not be searched. Enter the address instead.',
  cloud_sign_in_cancelled: 'Frameleaf Cloud sign-in was cancelled.',
  cloud_sign_in_timeout: 'Frameleaf Cloud sign-in timed out. Try again.',
  cloud_sign_in_failed: 'Frameleaf Cloud did not complete the sign-in. Try again.',
  cloud_account_unavailable: 'Frameleaf Cloud could not be reached. Check your connection and try again.',
  cloud_sign_in_required: 'Your Frameleaf Cloud session ended. Sign in again.',
  cloud_exchange_unsupported: 'This server does not accept Frameleaf Cloud sign-in yet. Sign in with its address, email and password.',
  cloud_server_unreachable: 'None of this server’s addresses answered. Check that it is online, or try again on its home network.',
  cloud_server_offline: 'This server is offline. Try again when it is back.',
  wallet_step_up_required: 'Raising the cap or turning on auto-reload needs a fresh sign-in on frameleaf.cloud. Open your account settings to change it there.',
};
export function connectionError(error: unknown): string {
  const code = error instanceof Error ? error.message : typeof error === 'string' ? error : '';
  return Object.hasOwn(messages, code) ? messages[code]! : 'This operation could not finish. Check your connection and try again.';
}

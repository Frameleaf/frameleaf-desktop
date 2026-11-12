// User-facing copy for the error and status codes the Rust side returns. test/errors.test.ts reads the codes
// from src-tauri/src and fails when one has no copy here. A component keeps its own wording only where its
// screen needs different words for a code (a small override table that says why); LocalHost.svelte still
// holds the copy for the codes only it shows.
const messages: Record<string, string> = {
  media_copy_exit_blocked: 'Finish or cancel the media copy, or wait for the update before quitting Frameleaf.',
  local_host_active: 'Stop local management before connecting to another server.',
  worker_setup_unavailable: 'Your server could not authorize AI processing. Check its connection and permissions, then try Resume again.',
  worker_resume_offline: 'Your server did not answer. Check that it is online, then try Resume again.',
  worker_resume_awaiting_approval: 'An administrator on your server needs to approve this computer for AI processing.',
  worker_resume_unsupported_server: 'Your server does not accept AI processing from this computer. Update the server, then try Resume again.',
  // ponytail: these states drop the underlying error, so the copy covers both an interruption and a refusal.
  worker_resume_enrollment_failed: 'This computer could not register with your server. Try Resume again. If it keeps failing, ask the person who runs your server to check this computer in the server’s settings.',
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
  server_http_401: 'Your server did not accept this sign-in. Check your email and password, or sign in again if your session ended.',
  server_http_403: 'Your server did not permit this sign-in.',
  verification_required: 'This needs Two-Step Verification.',
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
  worker_control_unsaved: 'AI processing couldn’t start, and its saved setting couldn’t be restored. Unlock your credential store, then choose Pause or Resume again.',
  server_identity_unverified: 'This server couldn’t prove it is the server your Frameleaf account lists. Check the address, or sign in with the server’s own sign-in.',
  server_identity_keys_unavailable: 'Frameleaf can’t confirm this server’s identity yet. Update the server, or sign in with its own sign-in.',
  cloud_server_not_on_account: 'This server isn’t on your Frameleaf account. Ask its owner to share it with you, or sign in with the server’s own sign-in.',
  cloud_email_invalid: 'Enter a valid email address.',
  cloud_exchange_interaction_required: 'Your Frameleaf account hasn’t approved this server yet. Sign in once with this server’s own sign-in, in your browser or with its email and password. After you approve it there, your Frameleaf account connects directly.',
  cloud_email_wrong_code: 'That Verification Code is incorrect. Check it and try again.',
  cloud_email_wrong_recovery_code: 'That Recovery Code is incorrect or was already used. Check it and try again.',
  cloud_email_wrong_password: 'That Password is incorrect. Check it and try again.',
  cloud_email_second_step_locked: 'Too many incorrect tries. Wait 15 minutes and try again, or use a Passkey in your browser.',
  cloud_email_account_blocked: 'This account can’t sign in. Contact Frameleaf support.',
  cloud_email_expired_code: 'This sign-in expired. Send a new Verification Code to continue.',
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
  cloud_server_address_unlisted: 'Your Frameleaf account doesn’t list this address for that server. Sign in with this server’s own sign-in, or connect on its home network.',
  server_not_frameleaf: 'That address answered, but not as a Frameleaf server. Check the address.',
  wallet_step_up_required: 'Raising the cap or turning on auto-reload needs a fresh sign-in on frameleaf.cloud. Open your account settings to change it there.',
  // Unified sign-in on a server: the second step of a sign-in, and a request refused until Two-Step Verification.
  sign_in_code_wrong: 'That Verification Code didn’t work. Check it and try again. If it keeps failing, start again with your Password.',
  sign_in_recovery_code_wrong: 'That Recovery Code didn’t work, or it was already used.',
  sign_in_code_invalid: 'Enter the 6-digit Verification Code, or one of your Recovery Codes.',
  sign_in_too_many_attempts: 'Too many attempts. Wait a few minutes, then try again.',
  sign_in_two_step_unsupported: 'This account uses Two-Step Verification, and this server can’t finish that in this app yet. Update the server, or sign in another way.',
  server_refused_verification_required: 'This needs Two-Step Verification.',
  server_refused_two_factor_setup_required: 'This server needs Two-Step Verification on every sign-in. Set it up on the server’s web page, then try again.',
  server_refused_frameleaf_sign_in_required: 'Away from home, sign in with your Frameleaf account to use this server.',
  // ---- external media copy (Backups) ----
  media_copy_package_unavailable: 'This package is no longer available as a complete, verified export. Refresh the list or verify it again in Photos.',
  media_copy_session_changed: 'Your server sign-in changed. Sign in again before saving a copy.',
  media_copy_destination_invalid: 'Choose a writable folder on a local drive. Check that the drive is still connected.',
  // media-copy.ts adds the file system to choose on this platform.
  media_copy_destination_unsupported: 'Choose a drive that can safely save a copy without replacing another file.',
  media_copy_busy: 'Wait for the current media copy or update to finish.',
  media_copy_server_unavailable: 'Could not check whether your library supports media copies. Check your connection and refresh the list.',
  media_copy_download_failed: 'The download stopped. Check your library connection and try again.',
  media_copy_destination_exists: 'This folder already has a copy with the same package ID. Choose another folder to keep both.',
  media_copy_space_insufficient: 'The selected drive does not have enough free space for this archive.',
  media_copy_archive_invalid: 'The downloaded package did not match its verified manifest. Try verifying the package again in Photos.',
  media_copy_write_failed: 'The copy could not be saved. Check the drive and its file-size limits.',
  media_copy_cancelled: 'Media copy cancelled.',
  // ---- offline albums ----
  offline_album_other_library: 'Offline storage belongs to another Library account. Return to that account to open its albums, or clear offline storage to start over on this computer.',
  offline_album_access_changed: 'Library access or album membership changed. Keep the album again from Photos if it is still available.',
  offline_album_storage_limit: 'The download exceeds the 2 GB offline cache.',
  offline_album_original_changed: 'An original changed during the download. Open the album in Photos and try again.',
  offline_album_cancelled: 'Download cancelled.',
  offline_library_unreachable: 'Frameleaf could not reach the Library to verify this album.',
  offline_album_save_failed: 'Frameleaf could not save the original to that folder.',
  offline_album_save_unsupported: 'Choose a folder on a drive that supports saving without replacing existing files.',
  offline_album_save_exists: 'Choose a new filename to save the original.',
  offline_album_busy: 'Frameleaf is finishing another offline operation. Try again in a moment.',
  // ---- photo folders and imports ----
  source_metadata_unavailable: 'File metadata could not be checked safely. Check folder access before resuming; staged data is kept.',
  source_folder_excluded: 'This folder is hidden or excluded. Choose an ordinary visible photo folder.',
  source_item_excluded: 'A file or folder became hidden or excluded. Copying stopped before reading it; existing staged data is kept.',
  source_item_invalid: 'This file is unsupported or linked. Some Windows cloud placeholders cannot be copied yet; export selected photos to an ordinary folder and try there.',
  source_item_unavailable: 'A selected file is unavailable. Check the folder before resuming.',
  source_item_empty: 'An empty file was skipped.',
  source_preview_policy_unavailable: 'A download-free folder preview could not be enabled. No preview was started. Try again after restarting the app.',
  source_inventory_partial: 'The scan reached its safety limit. Choose a smaller photo subfolder for this copy.',
  source_inventory_unreadable: 'Some entries could not be inspected. Check folder and drive access before preparing the copy again.',
  source_no_media: 'No supported photo or video files were found in this folder.',
  source_copy_budget_exceeded: 'This copy exceeds the server’s current size limits. Choose a smaller subfolder or remove unsupported large files from the selected scope.',
  source_staging_overlap: 'Choose a photo folder outside the app’s own data folder.',
  source_identity_unavailable: 'The filesystem could not provide a reliable file identity. Copying stopped; staged originals are kept. Try an ordinary local photo folder.',
  source_root_changed: 'This is no longer the folder you approved. Remove its permission and choose the folder again.',
  source_watch_local_required: 'Choose a local folder for automatic import.',
  source_watch_history_full: 'This watched folder reached its import history limit. Existing verified copies are kept.',
  source_run_terminal: 'The server stopped this copy. Remove the folder permission before starting again.',
  source_item_changed: 'A selected file changed after the scan. This copy is paused; the original and staged data are kept.',
  source_cloud_copy_pending: 'This Windows cloud folder can be previewed, but copying its placeholders is still being implemented. Export originals to an ordinary local folder for now.',
  source_capacity_unavailable: 'Available storage space could not be checked. Reconnect the photo-source and app-storage volumes, then resume.',
  source_capacity_insufficient: 'There is not enough free space for this original and its staged copy. Free space on the photo-source and app-storage volumes, then resume.',
  source_run_paused: 'Your server paused this copy before another original was staged. Resume explicitly when ready.',
  source_server_processing: 'Your server is still finishing this photo. Its staged original is retained; resume the copy when the server is ready.',
  source_receipt_invalid: 'The server did not confirm the expected healthy original. Copying stopped and the staged original was retained.',
  source_journal_invalid: 'Saved copy progress could not be verified. Staged originals are retained; do not remove them while investigating.',
  source_journal_write_failed: 'Copy progress could not be saved. Check local disk space and access before resuming; staged originals are retained.',
  source_stop_confirmation_pending: 'Copying stopped on this computer. The server could not confirm its stop yet; existing server copies are kept.',
  source_cache_cleanup_pending: 'The verified copy is on your server, but its local staging cache could not be cleared. Check local file access before resuming.',
  source_upload_budget_required: 'This saved copy needs an upload allowance before it can send original data. Approve the displayed amount, then resume.',
  source_upload_budget_exhausted: 'This copy reached its upload allowance. Staged originals are kept. Approve more upload data to retry.',
  source_copy_cancelled: 'Copying is paused. Resume when you are ready.',
  source_selection_changed: 'The folder selection expired. Choose the folder again.',
  source_remove_previous_approval: 'Remove the existing folder permission before choosing another folder.',
  source_photo_session_changed: 'This folder permission belongs to an earlier sign-in. Remove it and approve the folder again.',
  source_approval_invalid: 'The saved folder permission no longer matches this connection. Remove it before continuing.',
  source_server_update_required: 'Your server needs the desktop photo-source update.',
  source_registration_unavailable: 'The server could not be reached. The local permission is saved; retry registration when connected.',
  source_registration_response_invalid: 'The server did not confirm this exact folder permission. Copying remains stopped.',
  source_choose_photo_subfolder: 'Choose a photo folder inside your home folder, rather than your entire home folder.',
  source_package_requires_provider: 'Apple Photos libraries need the Photos connection. Choose an ordinary folder here.',
  source_folder_unavailable: 'This folder is unavailable. Check that its drive is connected and you have access.',
  source_account_unavailable: 'This OneDrive folder moved or is unavailable. Choose its new location.',
  source_camera_unavailable: 'Reconnect the original camera or card, then choose its folder to resume.',
  source_camera_changed: 'This folder or card does not match the approved import. Choose the original card or remove this permission to preview a new import. Verified copies stay in your library.',
  source_camera_identity_unavailable: 'This card could not be identified safely. Remove this permission and preview it again to start a new import.',
  source_drop_limit: 'Select one folder or up to 100 photos and videos from the same folder.',
  source_drop_mixed: 'Select one folder or choose photos and videos from the same folder.',
  source_drop_existing: 'Finish or remove the current import before starting another.',
  source_album_permission_required: 'You no longer have permission to add photos to this album. Copies already verified stay in your library.',
  source_album_unavailable_for_write: 'This album was removed or you can no longer add photos to it. Verified copies stay in your library.',
  source_album_missing: 'This album could not be found. Copies already verified stay in your library.',
  source_album_asset_missing: 'The album could not find the verified photo. Check it in your library before retrying.',
  source_album_selection_changed: 'The album name or sharing changed. Choose the destination again.',
  source_album_selection_invalid: 'Choose an album from your current library.',
  source_album_response_invalid: 'Your library could not confirm the album operation. Retry when it is available.',
  source_album_attachment_failed: 'Your library did not add this photo to the album. The verified copy stays in your library.',
  // ---- Manager: pairing, requests, backups and restores ----
  manager_already_paired: 'Disconnect the paired Manager before authorizing another installation.',
  manager_already_claimed: 'Manager is already configured. Retry with its existing password.',
  manager_claim_interrupted: 'Manager setup could not be confirmed. Retry with the same password; an existing administrator will not be replaced.',
  manager_claim_proof_changed: 'The private Manager setup proof could not be verified. Check the local installation before retrying.',
  manager_login_details_invalid: 'Enter your Manager password. New Manager passwords need at least 14 characters.',
  native_manager_not_ready: 'Prepare local Manager before authorizing management.',
  native_host_busy: 'Local management is starting or stopping. Wait for that step to finish.',
  manager_recent_auth_required: 'Enter your Manager password to authorize this action.',
  manager_invalid_credentials: 'The Manager password was not accepted. Try again.',
  manager_unreachable_or_certificate_invalid: 'Could not reach Manager. Check its address, connection and certificate, then check the existing request before starting another.',
  manager_pairing_interrupted: 'Pairing was interrupted. Check Manager and try pairing again.',
  manager_pair_again: 'This computer’s Manager access expired or was revoked. Disconnect and pair again with Manager.',
  manager_pairing_expired: 'This computer’s Manager access expired. Disconnect and pair again with Manager.',
  manager_scope_denied: 'This Manager grant does not allow that action.',
  manager_recovery_approval_required: 'Disconnect Manager, then pair again with backup recovery permission.',
  manager_recovery_unavailable: 'Backup review needs an updated native Frameleaf Manager.',
  manager_review_busy: 'Another backup review is still running. Check its existing request.',
  manager_review_changed: 'This review could not be matched to the current backup and installation.',
  manager_review_failed: 'The backup could not be verified for recovery.',
  manager_backup_unavailable: 'Database backups are not available in this Manager.',
  manager_restore_pending: 'Keep the existing database restore request until its outcome is confirmed.',
  manager_restore_review_required: 'Review this backup again before confirming a database restore.',
  native_restore_review_expired: 'The backup review expired before this restore was accepted. Review the backup again.',
  native_restore_review_not_ready: 'This backup review is not ready. Check it before restoring.',
  native_restore_runtime_change_required: 'This backup needs a different server runtime. Keep the current library and update the recovery runtime first.',
  manager_review_pending: 'Finish checking the current review before choosing another backup.',
  manager_operation_pending: 'Resolve the existing request before starting another action.',
  manager_operation_in_progress: 'Another Manager operation is active. Resolve it in Manager before starting a new action.',
  manager_operation_not_recoverable: 'This operation cannot be resumed now. Check its latest state in Manager.',
  manager_local_state_unavailable: 'The request receipt could not be saved on this computer. Keep this window open and check the existing operation.',
  manager_installation_changed: 'Manager now identifies a different installation. Verify it before pairing again.',
  manager_pairing_binding_changed: 'Manager returned different pairing details. Pairing stopped; verify the Manager installation.',
  manager_clock_skew: 'This computer’s clock and Manager’s clock differ by more than a minute. Set the date and time automatically on both, then try again.',
  manager_https_required: 'Use an HTTPS address for a Manager reached over the internet. HTTP works for a Manager on this computer or your home network, such as http://192.168.1.10:2282.',
  desktop_operation_not_authorized: 'Manager no longer lists that operation for this installation. Refresh to see its current state.',
  desktop_transport_refused: 'Manager refused this connection. Check that the Manager address matches the one Manager is configured with.',
  desktop_pairing_unavailable: 'Manager could not complete this pairing. Try pairing again.',
  desktop_pairing_invalid: 'Manager could not complete this pairing. Try pairing again.',
  manager_device_changed: 'This computer’s device key changed. Revoke its old Manager access with your Manager password, then pair again.',
  manager_certificate_invalid: 'Enter one valid public PEM certificate for Manager.',
  manager_certificate_approval_changed: 'The certificate changed after approval. Review its fingerprint again.',
  manager_certificate_approval_required: 'Review and approve this Manager certificate before pairing.',
  manager_grant_not_saved_revoke_in_manager: 'Manager access could not be saved. Revoke the newly created grant in Manager before retrying.',
  manager_http_certificate_invalid: 'Certificates apply to HTTPS connections. Use HTTP without a certificate or enter an HTTPS address.',
  manager_origin_invalid: 'Enter only Manager’s HTTP or HTTPS address, without a path or sign-in details.',
  manager_rate_limited: 'Manager has temporarily limited requests. Wait before trying again.',
  native_runtime_busy: 'The server is starting or stopping. Let it finish before retrying the backup.',
  native_backup_owner_unavailable: 'The server process state needs review. Check Manager before retrying this backup.',
  native_backup_owner_changed: 'Server ownership changed during backup recovery. Check Manager before resuming.',
  native_shutdown_unconfirmed: 'Database shutdown was not confirmed, so this operation stays locked. Check its state, then resume to verify shutdown.',
  native_backup_journal_invalid: 'Backup recovery records could not be verified. Keep the existing operation and review it in Manager.',
  native_backup_verification_failed: 'The backup could not be verified. The operation stays locked; review it before resuming.',
  native_checkpoint_unavailable: 'The database checkpoint is unavailable. Check the native runtime and operation state in Manager.',
  native_library_identity_invalid: 'The library recovery identity could not be verified. Review the installed profile in Manager.',
  native_backup_engine_changed: 'The installed backup engine could not be verified. Repair the signed runtime before retrying.',
};

/** Why AI processing on this computer is not running, for the codes that can stop it. */
export type WorkerReason =
  | 'network' | 'download' | 'storage' | 'not-enabled' | 'removed' | 'memory' | 'runtime' | 'restart' | 'checks'
  | 'renewing' | 'update' | 'power' | 'metered' | 'resumed' | 'by-you' | 'setup-mismatch' | 'credential-store' | 'history';

// Copy shared by a family of backend codes: [worker reason or '', what happened and what to do, codes].
// Every code is listed by name, so test/errors.test.ts still fails when the backend adds one without copy.
const families: readonly (readonly [WorkerReason | '', string, string])[] = [
  // ---- this app and this computer ----
  ['', 'This window can’t use that feature. Quit and reopen Frameleaf, then try again.', 'window_origin_invalid native_access_denied'],
  ['', 'This computer’s system isn’t supported for AI processing yet. Photos remain available.', 'platform_unsupported architecture_unsupported'],
  ['', 'This computer’s date and time look wrong. Correct them, then try again.', 'clock_invalid'],
  ['', 'Enter your email and password.', 'login_details_invalid'],
  ['', 'Your browser could not be opened. Check that this computer has a default browser, then try again.', 'external_open_failed'],
  ['', 'Servers on this network could not be searched. Enter the address instead.', 'discovery_failed'],
  ['', 'The Photos window could not open. Try again.', 'photo_session_unavailable photo_window_unavailable'],
  ['', 'Sign in to your Frameleaf library first.', 'sign_in_required'],
  ['', 'Frameleaf couldn’t change the File Explorer Send to shortcut. Check the Send to folder, then try again.', 'explorer_shortcut_conflict explorer_shortcut_unavailable'],
  ['', 'Frameleaf could not check for updates. Check your connection and try again.', 'update_check_failed'],
  ['', 'A different update was published while this one was starting. Check for updates again.', 'update_changed'],
  ['', 'The update could not be installed. Try again later.', 'update_install_failed'],
  ['', 'Stop local management before updating Frameleaf.', 'update_host_active'],
  ['', 'Your library on this computer is still shutting down, or did not shut down cleanly. Start the photo server in Manager and stop it there, then update Frameleaf.', 'update_library_not_idle'],
  ['', 'Finish or cancel the media copy before updating Frameleaf.', 'update_media_copy_active'],
  ['', 'Choose a daily cap between $1 and $1,000.', 'wallet_daily_cap_invalid'],
  ['', 'Nothing was changed. Choose a new cap or auto-reload setting first.', 'wallet_nothing_to_change'],
  ['', 'Those remote access settings could not be read. Reload the page and try again.', 'remote_settings_invalid'],
  // ---- saved sign-in on this computer ----
  ['credential-store', 'Another Frameleaf task is using the saved sign-in. Wait a moment, then try again.', 'credential_store_busy'],
  ['credential-store', 'Frameleaf could not safely open its saved sign-in on this computer. Quit and reopen Frameleaf, then try again.', 'credential_store_lock_invalid credential_store_lock_unavailable'],
  // ---- Frameleaf Cloud ----
  ['', 'Frameleaf Cloud’s address is not valid. Check it, then try again.', 'cloud_address_invalid'],
  ['', 'Frameleaf Cloud sent an answer this app could not read. Try again, or update Frameleaf.', 'cloud_response_invalid'],
  ['', 'Your Frameleaf account lists no secure address for this server. Connect on its home network, or sign in with the server’s own address.', 'cloud_server_has_no_https_address'],
  ['', 'That server could not be identified. Refresh your list of servers and try again.', 'cloud_server_invalid'],
  ['', 'Frameleaf Cloud did not complete the sign-in. Try again.', 'cloud_sign_in_invalid cloud_sign_in_state_mismatch cloud_sign_in_no_refresh_token'],
  ['', 'Frameleaf could not wait for the sign-in to come back from your browser. Quit and reopen Frameleaf, then try again.', 'cloud_sign_in_listener_unavailable'],
  // ---- your server ----
  ['network', 'The connection to your server dropped. Check your network, then try again.', 'server_response_interrupted desktop_enrollment_interrupted worker_request_interrupted worker_session_setup_interrupted worker_input_interrupted'],
  ['update', 'Your server sent an answer this app could not read. Update Frameleaf and your server, then try again.', 'server_response_invalid server_response_too_large'],
  ['update', 'Your server does not accept AI processing from this computer. Update the server, then try again.', 'desktop_worker_session_unavailable'],
  ['setup-mismatch', 'This computer’s AI setup does not match your current sign-in. Sign out and sign in again to set it up again.', 'desktop_enrollment_required installation_identity_missing worker_session_required worker_association_changed worker_preference_invalid'],
  // ---- AI processing: models ----
  ['download', 'The AI model download did not finish. Check your connection, then try again.', 'model_download_unavailable model_download_interrupted'],
  ['download', 'A downloaded AI model file did not match what your server expects, so it was discarded. Try again to download it again.', 'model_download_invalid model_download_hash_mismatch'],
  ['', 'The selected AI models need downloading. Choose Download Models to allow it.', 'model_download_permission_required'],
  ['storage', 'Frameleaf could not save AI files on this computer. Free up disk space, then try again. Photos remain available.', 'model_file_create_failed model_file_write_failed model_file_publish_failed model_cache_publish_failed model_cache_remove_failed worker_cache_publish_failed app_data_directory_unavailable runtime_copy_failed runtime_store_write_failed runtime_store_directory_failed runtime_scratch_failed runtime_fixture_write_failed runtime_store_activation_failed runtime_store_activation_sync_failed'],
  ['', 'The AI model files on this computer changed or could not be read. Try again to check them again.', 'model_file_changed model_file_unavailable model_partial_invalid model_inventory_invalid model_path_invalid model_link_forbidden worker_cache_conflict'],
  ['update', 'Your server sent AI model details this app could not use. Update Frameleaf and your server, then try again.', 'model_catalogue_invalid model_plan_invalid model_challenge_invalid worker_model_inventory_invalid worker_model_binding_invalid worker_models_ambiguous worker_models_unavailable'],
  // ---- AI processing: the runtime that comes with Frameleaf ----
  ['runtime', 'This build does not include a signed AI runtime yet. Photos remain available.', 'runtime_pack_unavailable'],
  ['runtime', 'The AI runtime that comes with Frameleaf is missing or could not be verified. Install Frameleaf again, then try again. Photos remain available.', 'app_resources_unavailable release_policy_invalid runtime_file_unavailable runtime_manifest_invalid runtime_manifest_incompatible runtime_signature_invalid runtime_artifact_changed runtime_artifact_invalid runtime_interpreter_unapproved runtime_inventory_failed runtime_inventory_limit runtime_inventory_mismatch runtime_link_forbidden runtime_path_invalid runtime_root_invalid runtime_size_invalid runtime_special_file_forbidden runtime_read_failed runtime_release_identity_changed runtime_device_observer_invalid runtime_device_entrypoint_invalid'],
  ['', 'GPU acceleration could not be used on this computer, so AI processing runs on the processor instead.', 'provider_device_ineligible provider_failed worker_provider_unavailable'],
  ['restart', 'The AI runtime could not start, or stopped unexpectedly, on this computer. Quit and reopen Frameleaf, then try again.', 'runtime_start_failed runtime_gate_failed runtime_port_invalid runtime_port_unavailable runtime_process_invalid runtime_process_owner_failed runtime_process_shutdown_unconfirmed runtime_process_status_failed runtime_process_state_unavailable runtime_process_stop_failed runtime_process_stopped runtime_not_ready runtime_health_invalid runtime_client_failed runtime_prediction_interrupted runtime_prediction_invalid runtime_prediction_refused runtime_activation_failed runtime_preparation_failed'],
  ['restart', 'Another copy of Frameleaf is using the AI files on this computer. Close it, then try again.', 'runtime_store_busy runtime_store_lock_failed'],
  ['', 'Frameleaf’s AI folder on this computer is not private to your account, so it was not used. Photos remain available. If this keeps happening, contact Frameleaf support.', 'runtime_store_directory_not_private runtime_store_directory_exists runtime_store_path_invalid runtime_store_lock_invalid runtime_store_privacy_inventory_limit'],
  ['history', 'AI processing needs recovery because this computer’s saved runtime history could not be verified. Photos remain available.', 'runtime_epoch_credential_missing runtime_epoch_identity_changed runtime_epoch_recovery_required runtime_epoch_record_invalid runtime_epoch_binding_invalid runtime_epoch_identity_invalid runtime_epoch_invalid runtime_epoch_operation_missing runtime_active_invalid runtime_active_epoch_changed runtime_store_file_invalid runtime_store_read_failed runtime_attestation_compression_failed runtime_attestation_too_large'],
  ['history', 'This AI runtime was rejected because it does not match this computer’s accepted runtime history. Photos remain available.', 'runtime_epoch_rollback runtime_epoch_reused'],
  // ---- AI processing: checks and tasks ----
  ['checks', 'This computer did not pass the checks for the selected AI models. Try again. If it keeps failing, this computer may not be able to run them.', 'worker_no_qualified_workloads worker_qualification_refused worker_qualification_invalid worker_predictor_qualification_changed runtime_qualification_binding_invalid runtime_qualification_failed runtime_qualification_input_invalid runtime_qualification_report_invalid runtime_qualification_timeout'],
  ['renewing', 'This computer’s approval for AI work ran out or changed. Try again to renew it.', 'worker_qualification_changed_or_expired worker_qualification_association_changed_or_expired worker_qualified_runtime_changed_or_expired worker_task_qualification_changed worker_challenge_association_changed worker_session_renewal_required worker_lease_expired worker_lease_lost worker_lease_refused worker_session_rejected worker_policy_changed worker_execution_deadline'],
  ['update', 'Your server and this computer could not agree on an AI task. Update Frameleaf and your server, then try again.', 'worker_challenge_invalid worker_challenge_request_invalid worker_claim_invalid worker_config_invalid worker_deadline_invalid worker_input_invalid worker_input_too_large worker_lease_invalid worker_path_invalid worker_payload_invalid worker_proof_invalid worker_result_invalid worker_result_refused worker_result_too_large worker_session_response_invalid worker_text_invalid'],
  ['', 'AI setup was stopped before it finished. Try again when you are ready.', 'worker_setup_cancelled worker_cancelled runtime_cancelled'],
  ['', 'AI setup could not finish. Photos remain available. Try again when your server and network are ready.', 'worker_setup_failed'],
  ['not-enabled', 'Your server keeps every AI task on its own destination, has it turned off, or uses a model this computer doesn’t support yet. A server administrator can send a task to computers in the server’s machine learning settings.', 'worker_no_eligible_workloads'],
  ['not-enabled', 'Your server’s settings for sharing this AI task with computers changed. A server administrator can review them in the server’s machine learning settings.', 'desktop_pool_config_changed desktop_pool_destination_changed desktop_pool_model_unavailable desktop_pool_route_changed desktop_route_review_required'],
  ['', 'Your server is not ready to check this AI task on this computer yet. Other tasks can continue.', 'desktop_nas_producer_unavailable desktop_nas_face_producer_unavailable desktop_nas_fixture_mismatch desktop_nas_model_unavailable desktop_nas_producer_changed desktop_nas_producer_expired desktop_model_profile_unavailable desktop_model_profile_changed desktop_clip_profile_unavailable desktop_face_profile_unavailable desktop_clip_space_unavailable desktop_clip_index_changed desktop_clip_index_dimensions desktop_clip_index_incompatible desktop_clip_index_invalid'],
  // ---- AI processing: why it is paused ----
  ['not-enabled', 'Your server is not using computers for AI processing right now. This computer checks again every few minutes.', 'worker_policy_required'],
  ['network', 'AI processing runs only on your server’s home network. This computer checks again every few minutes and when its network changes.', 'worker_lan_required'],
  ['by-you', 'Paused by you. This computer will stay paused after reopening the app.', 'user_paused'],
  ['resumed', 'This computer resumed or its clock changed. Rechecking the selected models before more work.', 'system_resumed'],
  ['power', 'Plug in this computer to continue AI processing.', 'on_battery'],
  ['power', 'Power status could not be read. AI processing is paused.', 'power_unknown'],
  ['metered', 'AI processing pauses on metered networks. Photos remain available.', 'metered_network'],
  ['metered', 'Network cost could not be determined. AI processing is paused.', 'network_unknown'],
  ['memory', 'Waiting for enough memory for the selected model. Closing other apps can help.', 'memory_low'],
  ['memory', 'Memory status could not be read. AI processing is paused.', 'memory_unknown'],
  ['', 'This computer’s power, network and memory could not be checked. AI processing is paused.', 'status_unavailable resource_status_unavailable'],
  // ---- photo folders and imports ----
  ['', 'This folder’s approval changed or is missing. Review the folder and approve it again.', 'source_approval_changed source_approval_required source_manifest_required source_run_changed source_control_invalid'],
  ['', 'That folder could not be read. Check that its drive is connected and that you can open it, then try again.', 'source_root_invalid source_root_unavailable source_folder_invalid source_folder_name_invalid source_home_unavailable source_discovery_failed source_inventory_failed'],
  ['', 'A file in this folder reported a size or date Frameleaf could not use. Copying stopped before reading it; the original is untouched.', 'source_inventory_size_invalid source_date_invalid'],
  ['', 'Frameleaf could not save its working files for this import on this computer. Free up disk space, then try again. Originals stay where they are.', 'source_stage_changed source_stage_invalid source_stage_unavailable source_stage_write_failed source_journal_too_large source_storage_unavailable source_copy_interrupted'],
  ['', 'This import’s saved progress could not be read. Quit and reopen Frameleaf, then try again.', 'source_history_invalid source_history_unavailable source_status_unavailable source_selection_unavailable'],
  ['', 'This import can no longer be retried from its history. Start a new import from the folder.', 'source_history_retry_unavailable'],
  ['', 'Your albums could not be loaded. Check the server connection and try again.', 'source_album_list_unavailable'],
  ['', 'Search for an album with a shorter name.', 'source_album_search_invalid'],
  ['', 'Some files in this folder are stored online only. Allow downloads for this folder to copy them.', 'source_download_permission_required'],
  ['', 'Your server could not be told to stop using this folder. Check the server connection and try again.', 'source_revocation_unavailable'],
  ['', 'The upload was interrupted. Check the server connection, then resume the copy.', 'source_upload_interrupted'],
  ['', 'Your server can’t accept this file’s size in one upload. Remove it from the selection, then resume the copy.', 'source_upload_capacity_exceeded'],
  ['', 'Your server can’t receive uploads from this app yet. Update the server, then try again.', 'source_upload_protocol_unsupported'],
  ['', 'Your server and this computer disagreed about an upload, so it stopped before anything was counted. Resume the copy to send it again.', 'source_upload_binding_invalid source_upload_journal_invalid source_upload_location_invalid source_upload_metadata_invalid source_upload_offset_invalid source_upload_receipt_invalid source_upload_response_invalid'],
  // ---- offline albums ----
  ['', 'The download stopped. Check your connection and try again.', 'offline_album_interrupted'],
  ['', 'This album has no originals to keep offline.', 'offline_album_no_originals'],
  ['', 'There is no offline album on this computer yet. Keep one from Photos first.', 'offline_album_none'],
  ['', 'Offline storage on this computer could not be opened. Try again, or clear offline storage to start over.', 'offline_album_response_invalid offline_album_storage_unavailable'],
  // ---- running your library on this computer: the server component ----
  ['', 'The server component installation could not be verified. Local management is blocked; your existing library has been preserved. Install the Frameleaf server component again, then try again.', 'host_manifest_invalid host_manifest_incompatible host_release_contract_invalid host_signature_invalid host_component_missing host_backup_engine_missing host_runtime_path_unavailable host_install_controller_changed host_install_runtime_changed host_install_program_invalid host_install_identity_invalid host_install_record_invalid host_install_path_invalid host_install_directory_invalid host_install_repair_path_invalid host_install_inventory_limit host_install_profile_changed host_install_profile_user_invalid host_install_profile_limit host_config_invalid host_control_config_invalid native_host_version_invalid native_host_config_invalid native_manager_layout_invalid native_manager_config_invalid'],
  ['', 'Installing the server component needs an administrator on this computer. Run its installer as an administrator, then try again.', 'host_install_administrator_required host_install_root_required'],
  ['', 'The server component could not be installed in its folder. Check that the drive has free space and that you can install apps, then run the installer again.', 'host_install_directory_failed host_install_directory_inaccessible host_install_location_unavailable host_install_record_failed host_install_profile_failed'],
  ['', 'This version of the server component is already installed. Choose it to continue.', 'host_install_version_exists'],
  ['', 'This library’s local server files could not be verified, so local management did not start. Your library has been preserved. Check that the library’s drive is connected, then try again.', 'host_state_invalid host_state_file_invalid host_state_not_private host_state_overlaps_runtime host_storage_unavailable host_profile_identity_changed host_profile_identity_unavailable host_database_reference_invalid'],
  ['', 'Choose a database folder that a cloud storage app does not sync.', 'host_database_cloud_state_unknown host_database_cloud_storage_forbidden'],
  ['', 'The selected drive does not have enough free space for the library database. Free up space or choose another drive.', 'host_database_space_insufficient'],
  ['', 'The selected drive can’t hold the library database. Choose a folder on a local drive that this computer can write to.', 'host_database_volume_unsupported'],
  ['', 'The local server could not start or stop cleanly on this computer. Your library has been preserved. Restart this computer, then try again.', 'host_agent_pipe_failed host_agent_restricted_launch_failed host_agent_source_invalid host_agent_start_failed host_readiness_failed host_readiness_timeout host_shutdown_failed native_host_setup_failed native_manager_launch_failed native_manager_start_timeout native_manager_bootstrap_failed native_manager_bootstrap_timeout native_manager_exited native_manager_process_owner_failed native_manager_state_unavailable native_manager_shutdown_unconfirmed'],
  ['', 'Local management is already running. Stop it first, then try again.', 'native_manager_already_running native_host_stop_required'],
  ['', 'Frameleaf and its server component could not understand each other. Update both to the same release, then try again.', 'host_control_arguments_invalid host_control_candidate_changed host_control_candidate_invalid host_control_command_invalid host_control_input_invalid host_control_output_unavailable host_checkpoint_protocol_invalid host_checkpoint_request_invalid host_restore_request_invalid host_restore_proof_invalid host_restore_safety_invalid'],
  ['', 'A backup or restore is already running. Wait for it to finish.', 'host_checkpoint_busy'],
  ['', 'The backup could not start. Check the photo server in Manager, then try again.', 'host_checkpoint_timeout host_checkpoint_unavailable'],
  ['', 'The restore could not be finished safely, so nothing was changed. Review the backup again in Manager before retrying.', 'host_restore_unavailable host_restore_activation_requires_review host_restore_activation_write_failed host_restore_media_changed'],
  ['', 'Frameleaf could not secure its connection to local Manager on this computer, so it did not start. Quit and reopen Frameleaf, then try again.', 'native_manager_unprotected native_manager_protection_unavailable native_manager_https_unverified native_manager_tls_invalid native_manager_receipt_invalid native_tls_binding_invalid native_tls_generation_failed native_tls_identity_changed native_tls_identity_expired native_tls_identity_invalid'],
  ['', 'The backup recovery key saved on this computer could not be read. Unlock your computer’s credential store, then try again.', 'native_backup_key_invalid native_backup_key_unavailable'],
  ['', 'This library’s backups are protected by a recovery key that is not on this computer. Recover the library with that key before continuing.', 'native_backup_key_recovery_required recovery_key_required'],
  // ---- Manager ----
  ['', 'Pair this computer with Manager before using this action.', 'manager_approval_required manager_pairing_required'],
  ['', 'The Manager access saved on this computer could not be read. Disconnect and pair again with Manager.', 'manager_credential_invalid'],
  ['', 'Manager has no photo server installation yet. Finish setup in Manager first.', 'manager_no_installation no_installation'],
  ['', 'Manager now identifies a different installation. Verify it before pairing again.', 'installation_changed'],
  ['', 'Manager could not finish this action. Check its latest state in Manager, then try again.', 'manager_operation_failed manager_request_failed operation_failed'],
  ['', 'This action was interrupted. Check its latest state in Manager before retrying.', 'operation_interrupted manager_response_interrupted'],
  ['', 'Manager sent an answer this app could not read. Update Frameleaf and Manager to the same release.', 'manager_request_invalid manager_response_invalid manager_response_too_large'],
  ['', 'Manager already received this request. Check the existing request instead of sending it again.', 'manager_request_key_reused manager_request_replayed'],
  ['', 'Another app is writing to the library’s media folder. Stop it, then try again.', 'other_media_writer_detected'],
  ['', 'The previous photo server can still start. Stop it and turn off its automatic start, then try again.', 'source_not_fenced previous_installation_not_fenced previous_autostart_enabled'],
  ['', 'The source changed after it was reviewed. Review it again.', 'source_changed_review_again'],
  ['', 'This backup is incomplete and can’t be used. Choose another backup.', 'backup_incomplete'],
  ['', 'The database folder isn’t available. Check that its drive is connected, then try again.', 'invalid_database_path database_path_not_mounted'],
];

// Codes the backend builds at run time, by prefix: `server_http_<status>`, `workload_<server refusal>`, …
const serverHttp = (status: string): string =>
  status === '404' ? 'Your server does not offer this feature. Update the server, then try again.'
  : status === '409' ? 'Your server’s settings changed while this was running. Try again.'
  : status === '429' ? 'Your server is busy. Wait a minute, then try again.'
  : ['408', '502', '503', '504'].includes(status) ? 'Your server did not answer in time. Check that it is online, then try again.'
  : status.startsWith('5') ? 'Your server ran into a problem. Try again in a few minutes, or ask the person who runs it.'
  : 'Your server did not accept this request. Update Frameleaf and your server, then try again.';
const built: readonly (readonly [string, (rest: string) => string])[] = [
  ['server_http_', serverHttp],
  ['server_refused_', () => 'Your server did not accept this change. Check the setting, or ask the person who runs your server.'],
  ['cloud_http_', () => 'Frameleaf Cloud could not complete that request. Try again in a few minutes.'],
  ['cloud_token_', () => 'Frameleaf Cloud did not accept this sign-in. Sign in again.'],
  ['cloud_sign_in_', () => 'Frameleaf Cloud did not complete the sign-in. Try again.'],
  ['source_upload_http_', status => status === '429' ? 'Your server is busy. Wait a minute, then resume the copy.' : 'Your server did not accept an upload. Check its source permission and free space, then resume the copy.'],
  ['worker_resume_', () => messages.worker_setup_unavailable!],
  ['workload_', rest => errorCopy(rest) ?? 'Your server is not ready to check this AI task on this computer yet. Other tasks can continue.'],
  ['local_port_in_use_', port => `Another program on this computer is using port ${port}, which Frameleaf needs. Close that program, then try again.`],
  ['resource_', rest => errorCopy(rest) ?? 'This computer’s power, network and memory could not be checked. AI processing is paused.'],
];

const shared = new Map<string, readonly [WorkerReason | '', string]>();
for (const [reason, text, codes] of families) for (const code of codes.split(' ')) shared.set(code, [reason, text]);

const generic = 'This operation could not finish. Check your connection and try again.';

/** The code a failed command or a status carries, or '' when it is not one. */
export function errorCode(error: unknown): string {
  // A request refused until Two-Step Verification arrives as an object carrying its code.
  const refused = typeof error === 'object' && error !== null ? (error as { code?: unknown }).code : undefined;
  const code = error instanceof Error ? error.message : typeof error === 'string' ? error : typeof refused === 'string' ? refused : '';
  return /^[a-z0-9]+(?:_[a-z0-9]+)*$/.test(code) && code.length <= 128 ? code : '';
}

/** Copy for a backend code, or null when this app has none for it. */
export function errorCopy(code: string): string | null {
  if (Object.hasOwn(messages, code)) return messages[code]!;
  const family = shared.get(code);
  if (family) return family[1];
  for (const [prefix, copy] of built) if (code.startsWith(prefix) && code.length > prefix.length) return copy(code.slice(prefix.length));
  return null;
}

/**
 * What to show for a failure: the copy for its code, or `fallback` with the code as a reference so
 * support can identify a failure this app has no words for yet. ErrorText.svelte renders both.
 */
export function describeError(error: unknown, fallback = generic): { message: string; reference: string | null } {
  const code = errorCode(error);
  const copy = code ? errorCopy(code) : null;
  return copy ? { message: copy, reference: null } : { message: fallback, reference: code || null };
}

/** describeError as one line of text, for the places that show a failure as a plain string. */
export function explainError(error: unknown, fallback = generic): string {
  const { message, reference } = describeError(error, fallback);
  return reference ? `${message} (Reference: ${reference})` : message;
}

/**
 * The two parts of an explainError line, so ErrorText.svelte can show the reference as small secondary
 * text. Any other text comes back whole, with no reference.
 */
export function splitReference(text: string): { message: string; reference: string | null } {
  const match = /^([\s\S]*) \(Reference: ([a-z0-9]+(?:_[a-z0-9]+)*)\)$/.exec(text);
  return match ? { message: match[1]!, reference: match[2]! } : { message: text, reference: null };
}

export function connectionError(error: unknown): string {
  return explainError(error);
}

// Worker reasons for codes whose copy lives in `messages` above or is built from a prefix.
const workerReasons: Readonly<Record<string, WorkerReason>> = {
  server_unreachable_or_certificate_invalid: 'network', cloud_server_unreachable: 'network',
  server_http_408: 'network', server_http_429: 'network', server_http_502: 'network', server_http_503: 'network', server_http_504: 'network',
  // The server answers 401 once it no longer knows this computer or its worker session.
  server_http_401: 'removed',
  server_http_404: 'update', desktop_protocol_unsupported: 'update',
  credential_store_locked_or_unavailable: 'credential-store', credential_store_unavailable: 'credential-store',
  credential_unlock_required: 'credential-store', credential_device_unlock_required: 'credential-store',
};

/** Why a worker status code stopped AI processing, or null when the code has no family. */
export function workerReason(code: string | null | undefined): WorkerReason | null {
  if (!code) return null;
  if (Object.hasOwn(workerReasons, code)) return workerReasons[code]!;
  const family = shared.get(code);
  if (family) return family[0] || null;
  for (const prefix of ['workload_', 'resource_']) if (code.startsWith(prefix)) return workerReason(code.slice(prefix.length));
  return null;
}

export function savedSignInNeedsRecovery(error: unknown): boolean {
  return ['credential_unlock_required', 'credential_confirmation_unavailable', 'credential_confirmation_changed'].includes(String(error));
}

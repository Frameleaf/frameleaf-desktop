export type AlbumDestination = { id: string; name: string; shared: boolean };

export const albumErrors: Record<string, string> = {
  source_album_permission_required: 'You no longer have permission to add photos to this album. Copies already verified stay in your library.',
  source_album_unavailable_for_write: 'This album was removed or you can no longer add photos to it. Verified copies stay in your library.',
  source_album_missing: 'This album could not be found. Copies already verified stay in your library.',
  source_album_asset_missing: 'The album could not find the verified photo. Check it in your library before retrying.',
  source_album_selection_changed: 'The album name or sharing changed. Choose the destination again.',
  source_album_selection_invalid: 'Choose an album from your current library.',
  source_album_response_invalid: 'Your library could not confirm the album operation. Retry when it is available.',
  source_album_attachment_failed: 'Your library did not add this photo to the album. The verified copy stays in your library.',
};

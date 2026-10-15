# Frameleaf Desktop

Native desktop apps for Windows, macOS and Linux, built on [Frameleaf/frameleaf-app PR #140](https://github.com/Frameleaf/frameleaf-app/pull/140).

## Setup modes

- **Connect to my server + help with AI processing**: sign in to an existing NAS server, manage it, and automatically enroll this computer as an authorized ML worker. This is the first delivery priority.
- **Run Frameleaf on this computer**: host the complete server locally through an installer-managed native runtime.

The desktop shell reuses the Frameleaf web photo UI. Native components provide background supervision, secure credentials, approved local photo sources, ML execution and OS integration. The browser remains supported.

Local photo-source work includes OneDrive folders and Apple Photos/iCloud through PhotoKit, with explicit copy/import or supported external-library references.

## Project resources

- [Jira project FD — Frameleaf Desktop](https://heroit.atlassian.net/jira/software/projects/FD/summary)
- [Confluence project home](https://heroit.atlassian.net/wiki/spaces/FD/overview)
- [Product and architecture plan](https://heroit.atlassian.net/wiki/spaces/FD/pages/73433098)
- [Implementation packets and acceptance gates](https://heroit.atlassian.net/wiki/spaces/FD/pages/73531393)

## Repository boundaries

This private repository owns the desktop shell, supervisor, native adapters, packaging and desktop tests. Proposed `desktop/...` paths in the planning documents map here. Backend, Manager, shared web and ML contract changes remain in `Frameleaf/frameleaf-app`. Shared UI, SDK and runtime artifacts must be pinned to reviewed versions; do not fork the photo application.

Planning baseline: PR #140 head `a85264d9e0973cce209d7539fb9fd5045488e7ea`. PR #140 remains draft/open and unmerged. This repository currently contains project setup and documentation only; desktop implementation and installed-device validation have not started.

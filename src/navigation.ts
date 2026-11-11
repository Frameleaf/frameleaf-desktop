export const pages = ['overview', 'sources', 'ai', 'manager', 'backups', 'cloud', 'wallet', 'remote'] as const;
export type Page = typeof pages[number];
const adminPages: readonly Page[] = ['cloud', 'wallet', 'remote'];

export function availablePage(value: unknown, admin: boolean): Page | null {
  const page = pages.find(item => item === value);
  return page && (admin || !adminPages.includes(page)) ? page : null;
}

export function restoredPage(raw: string | null, scope: string, admin: boolean): Page {
  if (!raw || !scope) return 'overview';
  try {
    const value = JSON.parse(raw);
    if (value?.scope === scope) return availablePage(value.page, admin) ?? 'overview';
  } catch { /* Invalid preferences are ignored. */ }
  return 'overview';
}

export function shortcutPage(event: Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'shiftKey' | 'altKey'>, mac: boolean): Page | null {
  if (event.shiftKey || event.altKey || event.ctrlKey === mac || event.metaKey !== mac) return null;
  return /^[1-8]$/.test(event.key) ? pages[Number(event.key) - 1] ?? null : null;
}

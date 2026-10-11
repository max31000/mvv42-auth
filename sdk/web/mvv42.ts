// mvv42-auth web SDK — copy this single file into an app frontend (e.g. src/lib/mvv42.ts).
// Source of truth: https://github.com/max31000/mvv42-auth/blob/main/sdk/web/mvv42.ts
// No dependencies. Works in any framework; see sdk/web/README section in docs/migration.md.
//
// Auth lives in HttpOnly cookies set by /auth/api/* (same origin), so there is no token in JS:
//  - mvv42Fetch: fetch with credentials; on 401 → one shared refresh → retry once.
//  - getMe: who am I (+ app access); null when the auth service is unavailable.
//  - requestLogin: ask the shell (or the top-level page) to show the Telegram login.
//  - onShellMessage / onShellTheme / startShellNavigationSync: shell <-> app postMessage protocol.

export const AUTH_API = '/auth/api';

export type AppAccessMode = 'public' | 'invite' | 'admin';

export interface AppAccess {
  id: string;
  /** App opens without login; login only unlocks extra features. */
  anonymous: boolean;
  access: AppAccessMode;
  /** The current user may use the app's authenticated features. */
  granted: boolean;
}

export interface Mvv42User {
  id: number;
  telegramId: number;
  name: string;
  username: string | null;
  photoUrl: string | null;
  isAdmin: boolean;
}

export interface Me {
  user: Mvv42User | null;
  apps: AppAccess[];
}

export type ShellMessage = { type: 'THEME'; scheme: 'light' | 'dark' } | { type: 'AUTH_CHANGED' };

// ---------------------------------------------------------------- session

let refreshInFlight: Promise<boolean> | null = null;

/**
 * POST /auth/api/refresh, at most one at a time: in-memory single-flight inside this page, and the
 * `mvv42-refresh` Web Lock across every same-origin tab and iframe (the refresh cookie is shared,
 * so parallel refreshes would race on token rotation).
 */
export function refreshSession(): Promise<boolean> {
  if (!refreshInFlight) {
    const run = (): Promise<boolean> =>
      fetch(`${AUTH_API}/refresh`, { method: 'POST', credentials: 'same-origin' }).then(
        (r) => r.ok,
        () => false,
      );
    const locks = globalThis.navigator?.locks;
    // lib.dom types request() as Promise<Promise<boolean>>; .then() unwraps it for the compiler.
    const attempt = locks ? locks.request('mvv42-refresh', run).then((ok) => ok) : run();
    refreshInFlight = attempt.finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

/**
 * `fetch` for the app's own API. Sends cookies (same-origin); on 401 refreshes the session once
 * (shared with concurrent callers) and retries the request once. Request bodies must be re-sendable
 * (string, FormData, Blob, URLSearchParams or a Request object — not a one-shot ReadableStream).
 */
export async function mvv42Fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const retryInput = input instanceof Request ? input.clone() : input;
  const options: RequestInit = { credentials: 'same-origin', ...init };

  const response = await fetch(input, options);
  if (response.status !== 401) return response;
  if (!(await refreshSession())) return response;
  return fetch(retryInput, options);
}

/** GET /auth/api/me (refreshes implicitly on the server). null = auth unavailable → behave as before auth. */
export async function getMe(): Promise<Me | null> {
  try {
    const response = await fetch(`${AUTH_API}/me`, { credentials: 'same-origin' });
    return response.ok ? ((await response.json()) as Me) : null;
  } catch {
    return null;
  }
}

/** Login UI lives in the shell: inside the iframe ask the shell, standalone go to `/?login=1&return=…`. */
export function requestLogin(serviceId: string): void {
  const shell = shellWindow();
  if (shell) {
    shell.postMessage({ type: 'AUTH_REQUIRED', serviceId }, location.origin);
    return;
  }
  location.assign('/?login=1&return=' + encodeURIComponent(safeReturnPath(location.pathname + location.search + location.hash)));
}

/**
 * The shell only accepts a same-origin path starting with `/` but not `//` or `/\` (spec §9.10). A path like
 * `//evil.example` (reachable as `https://mvv42.ru//evil.example`) would read as protocol-relative, so leading
 * slashes collapse to one; anything with a backslash falls back to `/`.
 */
function safeReturnPath(path: string): string {
  if (path.includes('\\')) return '/';
  return '/' + path.replace(/^\/+/, '');
}

// ---------------------------------------------------------------- shell protocol

/** The shell window when embedded in its iframe, otherwise null. */
function shellWindow(): Window | null {
  try {
    return window.parent !== window ? window.parent : null;
  } catch {
    return null;
  }
}

function isShellMessage(data: unknown): data is ShellMessage {
  if (typeof data !== 'object' || data === null) return false;
  const msg = data as { type?: unknown; scheme?: unknown };
  return msg.type === 'AUTH_CHANGED' || (msg.type === 'THEME' && (msg.scheme === 'light' || msg.scheme === 'dark'));
}

/**
 * Subscribes to THEME / AUTH_CHANGED from the shell. Only same-origin messages sent by the parent window
 * are accepted. Returns an unsubscribe function.
 */
export function onShellMessage(handler: (message: ShellMessage) => void): () => void {
  const listener = (event: MessageEvent) => {
    if (event.origin !== location.origin) return;
    const shell = shellWindow();
    if (!shell || event.source !== shell) return;
    if (isShellMessage(event.data)) handler(event.data);
  };
  window.addEventListener('message', listener);
  return () => window.removeEventListener('message', listener);
}

/** Receives the shell's resolved colour scheme; announces READY so the shell sends the current one. */
export function onShellTheme(serviceId: string, callback: (scheme: 'light' | 'dark') => void): () => void {
  const stop = onShellMessage((message) => {
    if (message.type === 'THEME') callback(message.scheme);
  });
  shellWindow()?.postMessage({ type: 'READY', serviceId }, location.origin);
  return stop;
}

/** Path inside the app: `/bonds/positions?x=1` → `/positions?x=1`. */
function appPath(serviceId: string): string {
  const prefix = `/${serviceId}`;
  const { pathname, search, hash } = location;
  let path = pathname;
  if (pathname === prefix) path = '/';
  else if (pathname.startsWith(prefix + '/')) path = pathname.slice(prefix.length);
  return path + search + hash;
}

/**
 * Keeps the shell's address bar (`#/<serviceId>/<path>`) in sync with the app's route: posts NAVIGATE on
 * start and after every pushState / replaceState / popstate / hashchange. No-op standalone.
 * Router-based apps may instead post from their router hook; pass `getPath` to customise the path.
 */
export function startShellNavigationSync(serviceId: string, getPath: () => string = () => appPath(serviceId)): () => void {
  const shell = shellWindow();
  if (!shell) return () => {};

  let last: string | null = null;
  const notify = () => {
    const path = getPath();
    if (path === last) return;
    last = path;
    shell.postMessage({ type: 'NAVIGATE', serviceId, path }, location.origin);
  };

  const originalPush = history.pushState;
  const originalReplace = history.replaceState;
  const patchedPush: History['pushState'] = function (this: History, ...args) {
    originalPush.apply(this, args);
    notify();
  };
  const patchedReplace: History['replaceState'] = function (this: History, ...args) {
    originalReplace.apply(this, args);
    notify();
  };
  history.pushState = patchedPush;
  history.replaceState = patchedReplace;
  window.addEventListener('popstate', notify);
  window.addEventListener('hashchange', notify);
  notify();

  return () => {
    if (history.pushState === patchedPush) history.pushState = originalPush;
    if (history.replaceState === patchedReplace) history.replaceState = originalReplace;
    window.removeEventListener('popstate', notify);
    window.removeEventListener('hashchange', notify);
  };
}

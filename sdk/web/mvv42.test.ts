import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  getMe,
  mvv42Fetch,
  onShellMessage,
  onShellTheme,
  refreshSession,
  requestLogin,
  startShellNavigationSync,
} from './mvv42';

const ORIGIN = window.location.origin;

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

/** Pretends the page is inside the shell's iframe; returns the fake parent window. */
function embed(): Window {
  const iframe = document.createElement('iframe');
  document.body.appendChild(iframe);
  const parentWindow = iframe.contentWindow!;
  Object.defineProperty(window, 'parent', { value: parentWindow, configurable: true });
  return parentWindow;
}

function unembed() {
  Object.defineProperty(window, 'parent', { value: window, configurable: true });
  document.body.innerHTML = '';
}

function post(data: unknown, origin = ORIGIN, source: MessageEventSource | null = window.parent) {
  window.dispatchEvent(new MessageEvent('message', { data, origin, source }));
}

afterEach(() => unembed());

describe('mvv42Fetch', () => {
  beforeEach(() => vi.stubGlobal('navigator', { ...navigator, locks: undefined }));

  it('sends same-origin credentials and returns non-401 responses as is', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('ok', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const res = await mvv42Fetch('/bonds/api/x');

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1]).toMatchObject({ credentials: 'same-origin' });
  });

  it('concurrent 401s trigger exactly one refresh, then each request is retried once', async () => {
    const refresh = deferred<Response>();
    let refreshed = false;
    const fetchMock = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url === '/auth/api/refresh') return refresh.promise.then((r) => ((refreshed = true), r));
      return Promise.resolve(new Response(null, { status: refreshed ? 200 : 401 }));
    });
    vi.stubGlobal('fetch', fetchMock);

    const pending = Promise.all([mvv42Fetch('/a'), mvv42Fetch('/b'), mvv42Fetch('/c')]);
    await vi.waitFor(() => expect(fetchMock.mock.calls.filter((c) => c[0] === '/auth/api/refresh')).toHaveLength(1));
    refresh.resolve(new Response(null, { status: 204 }));
    const results = await pending;

    expect(results.map((r) => r.status)).toEqual([200, 200, 200]);
    expect(fetchMock.mock.calls.filter((c) => c[0] === '/auth/api/refresh')).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledTimes(7); // 3 originals + 1 refresh + 3 retries
    expect(fetchMock.mock.calls.find((c) => c[0] === '/auth/api/refresh')![1]).toMatchObject({
      method: 'POST',
      credentials: 'same-origin',
    });
  });

  it('returns the original 401 when refresh fails, without retrying', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) =>
      Promise.resolve(new Response(null, { status: String(input) === '/auth/api/refresh' ? 403 : 401 })),
    );
    vi.stubGlobal('fetch', fetchMock);

    const res = await mvv42Fetch('/a');

    expect(res.status).toBe(401);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('retries a Request object with a fresh clone', async () => {
    const bodies: string[] = [];
    let call = 0;
    vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
      if (String(input) === '/auth/api/refresh') return new Response(null, { status: 204 });
      bodies.push(await (input as Request).text());
      return new Response(null, { status: call++ === 0 ? 401 : 200 });
    });

    const res = await mvv42Fetch(new Request(ORIGIN + '/a', { method: 'POST', body: 'payload' }));

    expect(res.status).toBe(200);
    expect(bodies).toEqual(['payload', 'payload']);
  });
});

describe('refreshSession', () => {
  it('runs under the shared navigator.locks lock when available', async () => {
    const request = vi.fn((_name: string, cb: () => Promise<boolean>) => cb());
    vi.stubGlobal('navigator', { ...navigator, locks: { request } });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));

    expect(await refreshSession()).toBe(true);
    expect(request).toHaveBeenCalledWith('mvv42-refresh', expect.any(Function));
  });

  it('reports false on network error', async () => {
    vi.stubGlobal('navigator', { ...navigator, locks: undefined });
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
    expect(await refreshSession()).toBe(false);
  });
});

describe('getMe', () => {
  it('returns the payload on 200', async () => {
    const me = { user: null, apps: [{ id: 'bonds', anonymous: false, access: 'admin', granted: false }] };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(me)));
    expect(await getMe()).toEqual(me);
  });

  it('returns null when auth is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('nope', { status: 502 })));
    expect(await getMe()).toBeNull();
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
    expect(await getMe()).toBeNull();
  });
});

describe('requestLogin', () => {
  it('in the shell iframe posts AUTH_REQUIRED to the parent with targetOrigin = own origin', () => {
    const parentWindow = embed();
    const postMessage = vi.spyOn(parentWindow, 'postMessage');

    requestLogin('bonds');

    expect(postMessage).toHaveBeenCalledWith({ type: 'AUTH_REQUIRED', serviceId: 'bonds' }, ORIGIN);
  });

  it('standalone navigates to the shell login with a return url', () => {
    const assign = vi.fn();
    vi.stubGlobal('location', { ...window.location, origin: ORIGIN, pathname: '/bonds/positions', search: '?x=1', hash: '#h', assign });

    requestLogin('bonds');

    expect(assign).toHaveBeenCalledWith('/?login=1&return=' + encodeURIComponent('/bonds/positions?x=1#h'));
  });
});

describe('shell messages', () => {
  it('delivers THEME and AUTH_CHANGED from the parent on the same origin', () => {
    embed();
    const handler = vi.fn();
    const stop = onShellMessage(handler);

    post({ type: 'THEME', scheme: 'dark' });
    post({ type: 'AUTH_CHANGED' });
    stop();
    post({ type: 'AUTH_CHANGED' });

    expect(handler.mock.calls.map((c) => c[0])).toEqual([{ type: 'THEME', scheme: 'dark' }, { type: 'AUTH_CHANGED' }]);
  });

  it('drops foreign origins, foreign sources and unknown or malformed messages', () => {
    embed();
    const handler = vi.fn();
    onShellMessage(handler);

    post({ type: 'AUTH_CHANGED' }, 'https://evil.example');
    post({ type: 'AUTH_CHANGED' }, ORIGIN, window); // not from the parent
    post({ type: 'THEME', scheme: 'purple' });
    post({ type: 'NAVIGATE', serviceId: 'x', path: '/' });
    post('AUTH_CHANGED');
    post(null);

    expect(handler).not.toHaveBeenCalled();
  });

  it('onShellTheme announces READY and receives the scheme', () => {
    const parentWindow = embed();
    const postMessage = vi.spyOn(parentWindow, 'postMessage');
    const cb = vi.fn();

    onShellTheme('bonds', cb);
    post({ type: 'THEME', scheme: 'light' });

    expect(postMessage).toHaveBeenCalledWith({ type: 'READY', serviceId: 'bonds' }, ORIGIN);
    expect(cb).toHaveBeenCalledWith('light');
  });
});

describe('startShellNavigationSync', () => {
  it('posts NAVIGATE with the app-relative path on start and on history changes', () => {
    const parentWindow = embed();
    const postMessage = vi.spyOn(parentWindow, 'postMessage');
    history.replaceState(null, '', '/bonds/');

    const stop = startShellNavigationSync('bonds');
    history.pushState(null, '', '/bonds/positions?tab=1');
    history.pushState(null, '', '/bonds/positions?tab=1'); // unchanged → no duplicate
    stop();
    history.pushState(null, '', '/bonds/after-stop');

    expect(postMessage.mock.calls).toEqual([
      [{ type: 'NAVIGATE', serviceId: 'bonds', path: '/' }, ORIGIN],
      [{ type: 'NAVIGATE', serviceId: 'bonds', path: '/positions?tab=1' }, ORIGIN],
    ]);
  });

  it('does nothing standalone', () => {
    const stop = startShellNavigationSync('bonds');
    history.pushState(null, '', '/bonds/x');
    stop();
  });
});

"""Existing Playwright call boundary: manifest-scoped final-page origin checks.

Wraps the already-admitted Playwright factory, not a new browser/provider/runtime.
Before and after each DOM action and after navigation, read the browser's own
page.url. Requested-host labels never substitute for final-page observation.
A non-HTTPS, unknown, redirected-out-of-scope or malformed page URL refuses
the action. The upstream ephemeral session still owns teardown and receipts.
"""
from __future__ import annotations

from contextlib import contextmanager
from urllib.parse import urlsplit


class FinalOriginRefused(ValueError):
    pass


def checked_host(url, origins):
    if not isinstance(url, str):
        raise FinalOriginRefused("FINAL_PAGE_URL_NOT_OBSERVED")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if parsed.scheme != "https" or not host:
            raise FinalOriginRefused("FINAL_PAGE_ORIGIN_NOT_AUTHORIZED")
        host = host.lower().rstrip(".")
    except (ValueError, AttributeError):
        raise FinalOriginRefused("FINAL_PAGE_ORIGIN_NOT_AUTHORIZED") from None
    for origin in origins:
        entry = origin.lower().rstrip(".")
        if entry == host or (entry.startswith("*.") and
                             (host == entry[2:] or host.endswith("." + entry[2:]))):
            return host
    raise FinalOriginRefused("FINAL_PAGE_ORIGIN_NOT_AUTHORIZED")


class _Locator:
    def __init__(self, locator, verify):
        self._locator = locator
        self._verify = verify

    def _call(self, name, *args, **kwargs):
        self._verify()
        outcome = getattr(self._locator, name)(*args, **kwargs)
        self._verify()
        return outcome

    def count(self):
        return self._call("count")

    def fill(self, *args, **kwargs):
        return self._call("fill", *args, **kwargs)

    def click(self, *args, **kwargs):
        return self._call("click", *args, **kwargs)

    def press(self, *args, **kwargs):
        return self._call("press", *args, **kwargs)

    def all_inner_texts(self):
        return self._call("all_inner_texts")


class _Frame:
    def __init__(self, frame, verify):
        self._frame = frame
        self._verify = verify

    def locator(self, selector):
        self._verify()
        return _Locator(self._frame.locator(selector), self._verify)


class _Page:
    def __init__(self, page, origins, observations):
        self._page = page
        self._origins = origins
        self._observations = observations

    def verify(self):
        host = checked_host(self._page.url, self._origins)
        self._observations.append(host)
        return host

    def goto(self, *args, **kwargs):
        response = self._page.goto(*args, **kwargs)
        self.verify()
        return response

    def locator(self, selector):
        self.verify()
        return _Locator(self._page.locator(selector), self.verify)

    def frame_locator(self, selector):
        self.verify()
        return _Frame(self._page.frame_locator(selector), self.verify)


class _Context:
    def __init__(self, context, origins, observations):
        self._context = context
        self._origins = origins
        self._observations = observations
        # Playwright navigation routing runs before the redirected request is
        # sent. A post-navigation page.url check alone is too late to prevent
        # an out-of-scope redirect from reaching its destination.
        def route_guard(route, request):
            # Every outbound request is a network action, not just top-level
            # navigation. A third-party script, frame, image or fetch must not
            # bypass the exact origin set admitted by the original manifest.
            try:
                checked_host(request.url, self._origins)
            except FinalOriginRefused:
                route.abort()
                return
            route.continue_()
        self._context.route("**/*", route_guard)

    def new_page(self):
        return _Page(self._context.new_page(), self._origins, self._observations)

    def close(self):
        return self._context.close()


class _Browser:
    def __init__(self, browser, origins, observations):
        self._browser = browser
        self._origins = origins
        self._observations = observations

    def new_context(self, *args, **kwargs):
        return _Context(self._browser.new_context(*args, **kwargs),
                        self._origins, self._observations)

    def close(self):
        return self._browser.close()


class _Chromium:
    def __init__(self, chromium, origins, observations):
        self._chromium = chromium
        self._origins = origins
        self._observations = observations

    def launch(self, *args, **kwargs):
        return _Browser(self._chromium.launch(*args, **kwargs),
                        self._origins, self._observations)


class _Playwright:
    def __init__(self, playwright, origins, observations):
        self.chromium = _Chromium(playwright.chromium, origins, observations)


@contextmanager
def guarded_factory(factory, allowed_origins, observations):
    with factory() as playwright:
        yield _Playwright(playwright, allowed_origins, observations)

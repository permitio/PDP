"""Debounce/coalesce forced-reload triggers for a single logical updater.

The PDP exposes API routes that force a *full* policy/data reload on every call
(``/policy-updater/trigger``, ``/data-updater/trigger`` and their legacy aliases).
Nothing dampens an authenticated caller (or a buggy SDK) hammering them, and each
forced reload amplifies straight onto the shared control plane - exactly when a
degraded control plane can least afford it. ``DebouncedTrigger`` holds the small
amount of coalescing *state* for one logical updater and decides, per call, whether
to actually run the reload or collapse it into a recent/in-flight one.

The class holds only state + policy; the actual reload work is passed in per call
(``run``). That lets the canonical and legacy-alias routes share a single instance
per updater (so an alternating canonical/legacy hammer still coalesces - both hit
the same control-plane resource) while each supplies its own ``run`` closure and
its own log context.
"""

import time
from collections.abc import Awaitable, Callable

from loguru import logger


class DebouncedTrigger:
    """Coalesces forced-reload triggers for one logical updater (policy or data).

    Semantics of :meth:`trigger` (in evaluation order):

    * ``window_seconds <= 0`` -> passthrough (debounce disabled): always run.
    * A reload is already **in flight** -> coalesce regardless of the window. Under a
      degraded control plane a single forced pull can run for minutes (the PDP configures
      many retries with exponential backoff), so a pure time-window check would still admit
      a *concurrent* full pull every ``window_seconds`` - the in-flight guard is what prevents
      that pile-up.
    * Otherwise, if the last successful reload was **within the window** -> coalesce.
    * Otherwise -> run, recording the completion time **only on success**.

    Recording ``_last_fired`` only on success is deliberate: a failed pull must not burn the
    window (a legitimate retry within ``window_seconds`` must still fire), and the exception is
    re-raised so the route surfaces it.
    """

    def __init__(self, name: str) -> None:
        # Short label used purely for logs, e.g. "policy" / "data".
        self._name = name
        # Monotonic seconds of the last *successful* reload; ``None`` until the first one.
        # Deliberately ``None`` and NEVER ``0.0``: ``time.monotonic()`` is ~seconds since boot
        # on Linux, so a ``0.0`` sentinel would read as "fired at boot" and silently coalesce
        # the very first real trigger on a freshly booted host.
        self._last_fired: float | None = None
        # True while a reload is running under this instance (see the in-flight guard).
        self._in_flight: bool = False

    async def trigger(self, run: Callable[[], Awaitable[None]], window_seconds: float) -> bool:
        """Run ``run`` (a coroutine factory doing the forced reload) unless it can be coalesced.

        Returns ``True`` if ``run`` was awaited, ``False`` if the trigger was coalesced into a
        recent/in-flight reload. A coalesced trigger is an immediate no-op success from the
        caller's perspective - it does NOT await the in-flight reload.
        """
        # 1. Debounce disabled -> passthrough. Any exception from ``run`` propagates.
        if window_seconds <= 0:
            await run()
            return True

        # 2. In-flight guard: collapse concurrent triggers into the one already running.
        if self._in_flight:
            logger.info(
                "Coalescing {} reload trigger: a forced reload is already in flight; collapsing into it.",
                self._name,
            )
            return False

        # 3. Window guard: collapse triggers that arrive within the debounce window of the
        #    last successful reload.
        if self._last_fired is not None:
            elapsed = time.monotonic() - self._last_fired
            if elapsed < window_seconds:
                logger.info(
                    "Coalescing {} reload trigger: within the {:g}s debounce window ({:.1f}s remaining).",
                    self._name,
                    window_seconds,
                    window_seconds - elapsed,
                )
                return False

        # 4. Fire. Single-worker assumption (the Rust supervisor spawns uvicorn with no
        #    --workers -> exactly one event loop): there is NO ``await`` between the guards
        #    above and this set, so the check-then-set is atomic and needs no lock. A second
        #    trigger cannot interleave until we ``await run()`` below, by which point
        #    ``_in_flight`` is already True and step 2 will coalesce it.
        self._in_flight = True
        try:
            await run()
            # Record completion time only on success so a failed pull does not burn the window.
            self._last_fired = time.monotonic()
            return True
        finally:
            self._in_flight = False

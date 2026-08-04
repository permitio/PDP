"""Debounce/coalesce forced-reload triggers for a single logical updater.

The PDP exposes API routes that force a *full* policy/data reload on every call
(``/policy-updater/trigger``, ``/data-updater/trigger`` and their legacy aliases).
Nothing dampens an authenticated caller (or a buggy SDK) hammering them, and each
forced reload amplifies straight onto the shared control plane - exactly when a
degraded control plane can least afford it. ``DebouncedTrigger`` holds the small
amount of coalescing *state* for one logical updater and decides, per call, whether
to actually dispatch the reload or collapse it into a recent/in-flight one.

The class holds only state + policy; the actual reload work is passed in per call
(``run``). That lets the canonical and legacy-alias routes share a single instance
per updater (so an alternating canonical/legacy hammer still coalesces - both hit
the same control-plane resource) while each supplies its own ``run`` closure and
its own log context.

WHAT ``run`` ACTUALLY DOES - read this before reasoning about the guards below.
Both updaters are fire-and-forget underneath, so ``await run()`` returns once the
reload has been *dispatched*, NOT once it has completed:

* policy - ``PolicyUpdater.trigger_update_policy`` is a single ``await queue.put(...)``
  onto an unbounded ``asyncio.Queue``. It cannot block and cannot fail. The real pull
  runs later in ``PolicyUpdater.handle_policy_updates``, which swallows every exception.
* data - ``DataUpdater.get_base_policy_data`` awaits ``_stop_polling_update_tasks()``
  and one data-source config GET, then hands the per-entry fetches to
  ``TasksPool.add_task`` (i.e. ``asyncio.create_task``). The retries/backoff configured
  via ``DATA_UPDATER_CONN_RETRY`` live inside those spawned tasks.

Two consequences that the guards below cannot paper over:

1. ``_last_dispatched`` is a DISPATCH timestamp. A reload that later fails in the
   background still consumes the window. There is no "only on success" guarantee to
   be had at this layer without an upstream OPAL change.
2. The in-flight window covers the dispatch only - a queue put (policy), or the config
   GET plus task hand-off (data). It is still worth having: that config GET has no
   explicit timeout and falls back to aiohttp's 5-minute default, so it genuinely can
   stall, and the guard is what stops concurrent triggers from piling up behind it.
"""

import math
import time
from collections.abc import Awaitable, Callable

from loguru import logger

# Upper bound for the debounce window. The value is remote-config overridable from the
# control plane, so an unclamped fat-finger (a stray "600000") would wedge every forced
# reload fleet-wide with no way to force a sync short of a rollout. Five minutes is far
# beyond any legitimate tuning range (ops guidance tops out around 60s).
MAX_DEBOUNCE_SECONDS: float = 300.0


def clamp_window(window_seconds: float) -> float:
    """Normalise a configured debounce window into the range the debouncer honours.

    Coerces defensively rather than trusting the type. ``confi.float`` casts from the
    ENVIRONMENT but its ``cast_from_json`` is ``no_cast``, so a remote config override from
    the control plane lands on the attribute VERBATIM - ``null`` and ``"30"`` both reach here
    unconverted. This function runs at startup as well as per request, so raising on a
    fat-fingered override would turn a bad config value into a PDP that will not boot.
    A numeric string is honoured; anything genuinely uninterpretable, and any non-finite
    value, collapses to 0 (debouncing disabled). The caller logs a warning when the
    effective window differs from what was configured.
    """
    try:
        window = float(window_seconds)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(window):
        return 0.0
    return min(max(window, 0.0), MAX_DEBOUNCE_SECONDS)


class DebouncedTrigger:
    """Coalesces forced-reload triggers for one logical updater (policy or data).

    Semantics of :meth:`trigger` (in evaluation order):

    * A reload is already **in flight** -> coalesce, and arm the trailing edge. This
      guard is unconditional: it applies even when ``window_seconds`` is 0, because
      "no time-based damping" should still never mean "two concurrent full pulls".
    * Otherwise, if ``window_seconds > 0`` and the last dispatch was **within the
      window** -> coalesce. No trailing edge here; staleness is bounded by
      ``window_seconds`` by construction, which is the entire point of the knob.
    * Otherwise -> dispatch, recording the dispatch time.

    **Trailing edge.** A trigger coalesced by the in-flight guard would otherwise be
    lost: the reload it collapsed into may have already read its data before the
    caller's change landed, and nothing would schedule a follow-up. Since an in-flight
    dispatch has no bounded duration, that staleness would be unbounded too. So the
    dispatching call re-runs **once** if any trigger arrived while it was running,
    capping the work at two dispatches per call.

    Be precise about what that does and does not promise. It bounds the damage from the
    in-flight guard; it is NOT a guarantee that every trigger is eventually served. This
    class never schedules future work - it only ever runs inside a caller's request - so
    a trigger arriving during the trailing run is coalesced and simply waits for somebody
    to trigger again. Closing that last gap needs a background timer task with its own
    lifecycle, which is deliberately out of scope here.
    """

    def __init__(self, name: str) -> None:
        # Short label used purely for logs, e.g. "policy" / "data".
        self._name = name
        # Monotonic seconds of the last *dispatch*; ``None`` until the first one.
        # Deliberately ``None`` and NEVER ``0.0``: ``time.monotonic()`` is ~seconds since boot
        # on Linux, so a ``0.0`` sentinel would read as "fired at boot" and silently coalesce
        # the very first real trigger on a freshly booted host.
        self._last_dispatched: float | None = None
        # True while a dispatch is running under this instance (see the in-flight guard).
        self._in_flight: bool = False
        # When the current dispatch started, so a coalesce log can report how long the
        # thing it is collapsing into has been running.
        self._in_flight_since: float | None = None
        # Set when the in-flight guard coalesces a trigger; consumed by the trailing edge.
        self._pending: bool = False
        # Coalesced-since-last-dispatch counter. Keeps the log quiet under the exact
        # hammering this class exists to absorb: the first suppression per dispatch logs
        # at INFO, the rest at DEBUG, and the dispatch logs the total.
        self._coalesced: int = 0

    async def trigger(self, run: Callable[[], Awaitable[None]], window_seconds: float) -> bool:
        """Dispatch ``run`` (a coroutine factory doing the forced reload) unless it can be coalesced.

        Returns ``True`` if ``run`` was dispatched, ``False`` if the trigger was coalesced into a
        recent/in-flight reload. A coalesced trigger is an immediate no-op success from the
        caller's perspective - it does NOT await the in-flight reload.
        """
        window_seconds = clamp_window(window_seconds)

        # 1. In-flight guard: collapse concurrent triggers into the one already running, and
        #    arm the trailing edge so this trigger is honoured rather than dropped.
        if self._in_flight:
            self._pending = True
            self._note_coalesced("a forced reload is already in flight ({:.1f}s so far)", self._in_flight_age())
            return False

        # 2. Window guard: collapse triggers that arrive within the debounce window of the
        #    last dispatch. Skipped entirely when the window is disabled (<= 0).
        if window_seconds > 0 and self._last_dispatched is not None:
            elapsed = time.monotonic() - self._last_dispatched
            if elapsed < window_seconds:
                self._note_coalesced(
                    "within the {:g}s debounce window ({:.1f}s remaining)", window_seconds, window_seconds - elapsed
                )
                return False

        # 3. Dispatch. Single-worker assumption (the Rust supervisor spawns uvicorn with no
        #    --workers -> exactly one event loop): there is NO ``await`` between the guards
        #    above and this set, so the check-then-set is atomic and needs no lock. A second
        #    trigger cannot interleave until we ``await run()`` below, by which point
        #    ``_in_flight`` is already True and step 1 will coalesce it.
        self._in_flight = True
        self._in_flight_since = time.monotonic()
        # Clear before running, so anything arriving from here on counts as "arrived during
        # this dispatch". NOT cleared in the finally below: if ``run`` raises, a trigger that
        # was coalesced into this failed dispatch must stay pending rather than be discarded -
        # the next dispatch clears it right here, at the point where it actually serves it.
        self._pending = False
        try:
            await run()
            self._last_dispatched = time.monotonic()
            self._log_dispatched()
            if self._pending:
                await self._run_trailing(run)
            return True
        finally:
            self._in_flight = False
            self._in_flight_since = None

    async def _run_trailing(self, run: Callable[[], Awaitable[None]]) -> None:
        """Re-dispatch once, for triggers that arrived while the first dispatch was running.

        Failures are logged and swallowed, never propagated. The caller executing this re-run
        already had its OWN dispatch succeed; handing it a 500 caused by somebody else's
        trigger would be both confusing and wrong (its request did what it asked). Losing the
        trailing reload is the lesser evil, and it is logged at ERROR.
        """
        self._pending = False
        logger.info(
            "Re-running {} reload (trailing edge): a trigger arrived while the previous one was in flight.",
            self._name,
        )
        try:
            await run()
        except Exception:  # noqa: BLE001
            logger.opt(exception=True).error(
                "Trailing {} reload failed. The triggers it was serving were not applied; "
                "the next trigger after the debounce window will retry.",
                self._name,
            )
            return
        self._last_dispatched = time.monotonic()
        self._log_dispatched()

    def _log_dispatched(self) -> None:
        """Report how many triggers the dispatch that just completed absorbed."""
        if not self._coalesced:
            return
        logger.info("Dispatched {} reload, absorbing {} coalesced trigger(s).", self._name, self._coalesced)
        # Reset only here, on a dispatch that actually completed. A dispatch that raised leaves
        # the count standing, so the triggers it failed to serve are still attributed to the
        # dispatch that eventually does serve them.
        self._coalesced = 0

    def _in_flight_age(self) -> float:
        """Seconds the current dispatch has been running (0.0 when nothing is in flight)."""
        if self._in_flight_since is None:
            return 0.0
        return time.monotonic() - self._in_flight_since

    def _note_coalesced(self, reason: str, *args: float) -> None:
        """Count a coalesced trigger and log it, loudly the first time and quietly thereafter."""
        self._coalesced += 1
        message = "Coalescing {} reload trigger: " + reason + "."
        # Only the first suppression per dispatch is worth an INFO line - under a hammer, one
        # INFO per suppressed request would make the mitigation amplify log volume into the
        # (unbounded, enqueue=True) logzio sink. The dispatch line reports the total.
        log = logger.info if self._coalesced == 1 else logger.debug
        log(message, self._name, *args)

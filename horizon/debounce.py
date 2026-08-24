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

IMPORT DIRECTION. This module must never import ``horizon.config``. ``config.py``
imports ``DEFAULT_DEBOUNCE_SECONDS`` from here to declare the setting's default, so
the edge is one-way (config -> debounce). Nothing here needs the config: ``trigger``
receives the window as a parameter.

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

Three consequences the guards below are built around:

1. ``_last_dispatched`` records the ATTEMPT, not the outcome - it is stamped in a
   ``finally``, so a dispatch that raises still consumes the window. This matters most
   under a degraded control plane: ``get_policy_data_config`` raises ``ClientError`` on
   any non-200, and a window consumed only by *successes* would leave the mitigation
   switched off in precisely the conditions it exists for. The one exception is
   cancellation, which means the attempt was abandoned rather than made.
2. The in-flight window covers the dispatch only - a queue put (policy), or the config
   GET plus task hand-off (data). It is still worth having: that config GET has no
   explicit timeout and falls back to aiohttp's 5-minute default, so it genuinely can
   stall, and the guard is what stops concurrent triggers from piling up behind it.
3. ``run`` is NEVER wrapped in ``asyncio.wait_for``. Cancelling ``get_base_policy_data``
   mid-flight is destructive: it awaits ``_stop_polling_update_tasks()`` (which cancels
   and clears every ``periodic_update_interval`` poller) BEFORE the config GET, and the
   pollers are only ever recreated at the very end of that same function. A timeout
   landing on the stalled GET would therefore leave every periodic data source
   permanently dead, with no error and no recovery short of an OPAL reconnect - strictly
   worse than the bounded, self-healing stall it would be "fixing". A stalled dispatch
   is made *observable* instead (see ``MAX_DISPATCH_SECONDS``), not cancellable.
"""

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from typing import Any, Literal

from loguru import logger

# Default debounce window. Single-sourced HERE rather than in config.py so that the
# fallback `clamp_window`/`resolve_window` apply to an uninterpretable value is the same
# number the setting declares as its default (see the import-direction note above).
DEFAULT_DEBOUNCE_SECONDS: float = 10.0

# Upper bound for the debounce window. The value is remote-config overridable from the
# control plane, so an unclamped fat-finger (a stray "600000") would wedge every forced
# reload fleet-wide with no way to force a sync short of a rollout. Five minutes is far
# beyond any legitimate tuning range (ops guidance tops out around 60s).
MAX_DEBOUNCE_SECONDS: float = 300.0

# How long a dispatch may run before we treat it as STALLED rather than merely slow.
# Purely an observability threshold - it never cancels anything (see consequence 3 in the
# module docstring). The awaited work is a task-cancel gather plus one small JSON GET, so
# a healthy dispatch is low single-digit seconds; past this the control plane is hung and
# every coalesce logs at ERROR so it is alertable instead of silent.
MAX_DISPATCH_SECONDS: float = 30.0

# Why a window ended up different from what was configured, for the caller's startup log.
WindowProblem = Literal["unparseable", "clamped"]


async def _sleep(seconds: float) -> None:
    """Indirection so the unit tests can drive the trailing timer without real time passing.

    Deliberately a module-level function looked up at call time, mirroring how this module's
    ``time`` reference is faked in ``test_debounce_unit.py``. Never ``from asyncio import
    sleep`` and never capture it in a default argument - both would defeat the monkeypatch.
    """
    await asyncio.sleep(seconds)


def resolve_window(value: Any, default: float = DEFAULT_DEBOUNCE_SECONDS) -> tuple[float, WindowProblem | None]:
    """Normalise a configured debounce window, reporting *why* it was changed.

    Coerces defensively rather than trusting the type. ``confi.float`` casts from the
    ENVIRONMENT but its ``cast_from_json`` is ``no_cast``, so a remote config override from
    the control plane lands on the attribute VERBATIM - ``null`` and ``"30"`` both reach here
    unconverted. A numeric string is therefore honoured, and honouring it must not be
    mistaken for a clamp (the old code compared ``float`` to the raw attribute and logged a
    false "out of range" warning for a perfectly valid ``"30"``).

    Fails SAFE, not open. Anything uninterpretable - ``None``, ``"tem"``, a non-finite, a
    negative - falls back to ``default``, leaving the mitigation ON. Only an explicit,
    parseable ``0`` disables the window. The previous behaviour collapsed all of these to
    ``0``, so a single control-plane typo silently switched off the very protection this
    module exists to provide, fleet-wide.

    Never raises: this runs at startup as well as per request, and a fat-fingered remote
    override must not turn into a PDP that will not boot.
    """
    try:
        window = float(value)
    except (TypeError, ValueError):
        return default, "unparseable"
    if not math.isfinite(window) or window < 0:
        return default, "unparseable"
    clamped = min(window, MAX_DEBOUNCE_SECONDS)
    return clamped, "clamped" if clamped != window else None


def clamp_window(value: Any, default: float = DEFAULT_DEBOUNCE_SECONDS) -> float:
    """The window :meth:`DebouncedTrigger.trigger` will actually honour. See :func:`resolve_window`."""
    return resolve_window(value, default)[0]


class DebouncedTrigger:
    """Coalesces forced-reload triggers for one logical updater (policy or data).

    Semantics of :meth:`trigger` (in evaluation order):

    * A reload is already **in flight**, or a **trailing run is already armed** -> coalesce,
      and mark the trigger pending. This guard is unconditional: it applies even when
      ``window_seconds`` is 0, because "no time-based damping" should still never mean "two
      concurrent full pulls".
    * Otherwise, if ``window_seconds > 0`` and the last dispatch was **within the window**
      -> coalesce, and arm the trailing edge.
    * Otherwise -> dispatch.

    **Trailing edge.** A coalesced trigger is never dropped. The reload it collapsed into
    already read the control plane *before* the caller's change landed, and this PDP is
    pubsub-driven with no periodic full-refresh cadence - so dropping it would lose the
    refresh permanently, which is exactly what PER-15248 forbids ("must not debounce so
    aggressively that a legitimately-needed reload is dropped"). Instead the debouncer arms
    a background task that re-runs once the window expires, which is what makes "staleness
    is bounded by ``window_seconds``" an actual guarantee rather than a hopeful comment.

    **The trailing run is a task, not part of a request.** It used to be awaited inline by
    whichever caller won the dispatch, which billed that caller for a second full reload it
    never asked for - against a 60s client timeout in the Rust server that fronts this app.
    The dispatching caller now returns as soon as its own dispatch is handed off, which is
    what its 200 already meant.

    **The chain terminates.** A trailing run re-arms only if ``_pending`` is set when it
    finishes, and ``_pending`` is written ``True`` in exactly one place: :meth:`trigger`, by
    an external caller. Nothing in the trailing path sets it. So the chain length is bounded
    by the number of real triggers and stops one run after they stop - it can never
    self-perpetuate into a standing 1-per-window load on the control plane. Under a sustained
    hammer it converges to one dispatch per ``window_seconds``, which is the intended damping.

    **What the trailing run serves.** It re-runs the ``run`` closure captured when it was
    armed - the first *coalesced* caller's on the window path, the *dispatcher's* on the
    in-flight path. The closures differ only in their ``data_fetch_reason`` log string, so
    this is a log-attribution detail, not a behavioural one.
    """

    def __init__(self, name: str) -> None:
        # Short label used purely for logs, e.g. "policy" / "data".
        self._name = name
        # Monotonic seconds of the last dispatch ATTEMPT; ``None`` until the first one.
        # Deliberately ``None`` and NEVER ``0.0``: ``time.monotonic()`` is ~seconds since boot
        # on Linux, so a ``0.0`` sentinel would read as "fired at boot" and silently coalesce
        # the very first real trigger on a freshly booted host.
        self._last_dispatched: float | None = None
        # True while a dispatch is running under this instance (see the in-flight guard).
        self._in_flight: bool = False
        # When the current dispatch started, so a coalesce log can report how long the
        # thing it is collapsing into has been running.
        self._in_flight_since: float | None = None
        # Set when a trigger is coalesced; consumed by the trailing edge.
        self._pending: bool = False
        # The armed trailing run, if any. Doubles as a guard (see guard 1) and as the strong
        # reference that keeps the task from being garbage collected mid-flight.
        self._trailing_task: asyncio.Task[None] | None = None
        # Coalesced-since-last-dispatch counter. Keeps the log quiet under the exact
        # hammering this class exists to absorb: the first suppression per dispatch logs
        # at INFO, the rest at DEBUG, and the dispatch logs the total.
        self._coalesced: int = 0

    async def trigger(self, run: Callable[[], Awaitable[None]], window_seconds: float) -> bool:
        """Dispatch ``run`` (a coroutine factory doing the forced reload) unless it can be coalesced.

        Returns ``True`` if ``run`` was dispatched, ``False`` if the trigger was coalesced into a
        recent/in-flight reload. A coalesced trigger is an immediate no-op success from the
        caller's perspective - it does NOT await the reload it collapsed into, and it is not
        dropped: a trailing run is armed to serve it once the window expires.
        """
        window_seconds = clamp_window(window_seconds)

        # 1. In-flight / already-armed guard: collapse concurrent triggers into the reload
        #    already running, or into the trailing run already scheduled to serve them.
        if self._in_flight or self._trailing_task is not None:
            self._pending = True
            self._note_in_flight_coalesce()
            return False

        # 2. Window guard: collapse triggers that arrive within the debounce window of the
        #    last dispatch, and arm the trailing edge so the trigger is served rather than
        #    dropped. Skipped entirely when the window is disabled (<= 0).
        if window_seconds > 0 and self._last_dispatched is not None:
            elapsed = time.monotonic() - self._last_dispatched
            if elapsed < window_seconds:
                self._pending = True
                self._note_coalesced(
                    "within the {:g}s debounce window ({:.1f}s remaining)", window_seconds, window_seconds - elapsed
                )
                self._arm_trailing(run, window_seconds)
                return False

        # 3. Dispatch. Single-worker assumption (the Rust supervisor spawns uvicorn with no
        #    --workers -> exactly one event loop): there is NO ``await`` between the guards
        #    above and this set, so the check-then-set is atomic and needs no lock. A second
        #    trigger cannot interleave until we ``await run()`` below, by which point
        #    ``_in_flight`` is already True and step 1 will coalesce it.
        self._in_flight = True
        self._in_flight_since = time.monotonic()
        # Clear before running, so anything arriving from here on counts as "arrived during
        # this dispatch" and is served by the trailing edge. Biases towards one redundant
        # run, never a lost one.
        self._pending = False
        cancelled = False
        try:
            await run()
            self._log_dispatched()
            return True
        except asyncio.CancelledError:
            # The attempt was ABANDONED, not made: client disconnect, or shutdown. Record no
            # dispatch (so the window is not consumed by work that never reached the control
            # plane) and arm nothing (on shutdown there would be nobody left to run it).
            cancelled = True
            raise
        finally:
            # INVARIANT: this block must never ``await``. The no-overlap argument for the two
            # guards rests on the handoff from ``_in_flight`` to ``_trailing_task`` being
            # atomic, which holds only while nothing here yields to the event loop.
            if not cancelled:
                # The ATTEMPT consumes the window - see consequence 1 in the module docstring.
                self._last_dispatched = time.monotonic()
                if self._pending:
                    self._arm_trailing(run, window_seconds)
            self._in_flight = False
            self._in_flight_since = None

    async def aclose(self) -> None:
        """Cancel any armed trailing run. Idempotent; safe to call with nothing armed.

        Wired to the app's ``shutdown`` event so a pending trailing reload does not outlive
        the event loop as a "Task was destroyed but it is pending" warning.
        """
        task = self._trailing_task
        if task is None:
            return
        task.cancel()
        # gather(return_exceptions=True) rather than a bare await: this runs on the shutdown
        # path, where re-raising the task's CancelledError could be mistaken for the shutdown
        # coroutine's own cancellation.
        await asyncio.gather(task, return_exceptions=True)

    def _arm_trailing(self, run: Callable[[], Awaitable[None]], window_seconds: float) -> None:
        """Schedule the trailing run. Called from ``finally`` blocks, so it must never raise.

        An exception escaping here would replace whatever was propagating AND discard the
        ``return True`` of a dispatch that actually succeeded, turning it into a 500.
        """
        if self._trailing_task is not None:
            return
        try:
            task = asyncio.create_task(self._run_trailing(run, window_seconds))
        except RuntimeError:  # no running loop - we are being torn down; nothing to schedule onto
            logger.opt(exception=True).error("Could not arm the trailing {} reload.", self._name)
            return
        self._trailing_task = task
        # Safety net for the one case ``_run_trailing``'s own ``finally`` cannot cover: a task
        # cancelled BEFORE its first step never runs its body at all, which would leave
        # ``_trailing_task`` set forever and coalesce every future trigger - a permanent wedge,
        # the exact failure this class exists to prevent.
        task.add_done_callback(self._on_trailing_done)

    def _on_trailing_done(self, task: "asyncio.Task[None]") -> None:
        """Clear the handle and surface anything that escaped the trailing task."""
        if self._trailing_task is task:
            self._trailing_task = None
        if not task.cancelled() and task.exception() is not None:
            # Retrieved here so it cannot resurface as "Task exception was never retrieved"
            # at garbage-collection time, detached from any useful context.
            logger.opt(exception=task.exception()).error("Trailing {} reload task failed.", self._name)

    async def _run_trailing(self, run: Callable[[], Awaitable[None]], window_seconds: float) -> None:
        """Serve the triggers coalesced since the last dispatch, once the window has expired.

        Failures are logged and swallowed, never propagated: nobody is awaiting this task, and
        the caller whose request armed it has long since been answered.
        """
        cancelled = False
        try:
            delay = self._time_until_window_expires(window_seconds)
            if delay > 0:
                logger.info(
                    "Scheduling a trailing {} reload in {:.1f}s to serve coalesced trigger(s).", self._name, delay
                )
                await _sleep(delay)
            # Cleared immediately before the run: anything arriving from here on counts as
            # "arrived during this run" and chains into one more trailing run.
            self._pending = False
            self._in_flight = True
            self._in_flight_since = time.monotonic()
            try:
                await run()
                self._log_dispatched()
            except asyncio.CancelledError:
                cancelled = True
                raise
            except Exception:  # noqa: BLE001
                logger.opt(exception=True).error(
                    "Trailing {} reload failed. The triggers it was serving were not applied; "
                    "the next trigger after the debounce window will retry.",
                    self._name,
                )
            finally:
                if not cancelled:
                    self._last_dispatched = time.monotonic()
                self._in_flight = False
                self._in_flight_since = None
        except asyncio.CancelledError:
            # Also catches cancellation during ``_sleep`` above, which the inner handler cannot
            # see. That is the COMMON case on shutdown - ``aclose`` usually finds this task
            # waiting out the window - and ``_pending`` is still set there, so without this the
            # ``finally`` below would happily arm a replacement task mid-teardown.
            cancelled = True
            raise
        finally:
            # Also await-free, for the same reason as the ``finally`` in ``trigger``. Clear the
            # handle BEFORE re-arming or the re-arm is immediately clobbered by the guard in
            # ``_arm_trailing``.
            if self._trailing_task is asyncio.current_task():
                self._trailing_task = None
            # Never chain while cancellation is propagating: the new task would be created
            # during loop teardown, after the cancel-all sweep has already run, and would be
            # left pending with nobody to await it.
            if self._pending and not cancelled:
                self._arm_trailing(run, window_seconds)

    def _time_until_window_expires(self, window_seconds: float) -> float:
        """Seconds until the debounce window is clear again (0.0 when it already is)."""
        if window_seconds <= 0 or self._last_dispatched is None:
            return 0.0
        return max(0.0, window_seconds - (time.monotonic() - self._last_dispatched))

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

    def _note_in_flight_coalesce(self) -> None:
        """Log a trigger absorbed by guard 1, escalating when the thing it waits on is stalled.

        The dispatch it is collapsing into cannot be cancelled (see consequence 3 in the module
        docstring), so a hung control-plane GET can hold the guard for aiohttp's 5-minute
        default. That must not be silent: past ``MAX_DISPATCH_SECONDS`` every coalesce logs at
        ERROR, which is the signal that forced reloads are currently absorbed rather than served.
        """
        if not self._in_flight:
            # Guard 1 also fires when only a trailing run is armed - no dispatch is running, the
            # trigger is simply already accounted for by scheduled work.
            self._note_coalesced("a trailing reload is already armed to serve it")
            return
        age = self._in_flight_age()
        if age > MAX_DISPATCH_SECONDS:
            self._note_coalesced(
                "a forced reload has been in flight for {:.1f}s (over the {:g}s a healthy dispatch takes) - "
                "the control plane looks stalled and forced reloads are being absorbed, not served",
                age,
                MAX_DISPATCH_SECONDS,
                stalled=True,
            )
            return
        self._note_coalesced("a forced reload is already in flight ({:.1f}s so far)", age)

    def _note_coalesced(self, reason: str, *args: float, stalled: bool = False) -> None:
        """Count a coalesced trigger and log it, loudly the first time and quietly thereafter."""
        self._coalesced += 1
        message = "Coalescing {} reload trigger: " + reason + "."
        # Only the first suppression per dispatch is worth an INFO line - under a hammer, one
        # INFO per suppressed request would make the mitigation amplify log volume into the
        # (unbounded, enqueue=True) logzio sink. The dispatch line reports the total. A stalled
        # dispatch is the exception: that one is alertable and must not be buried at DEBUG.
        if stalled:
            logger.error(message, self._name, *args)
            return
        log = logger.info if self._coalesced == 1 else logger.debug
        log(message, self._name, *args)

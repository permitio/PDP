"""Unit tests for :class:`horizon.debounce.DebouncedTrigger` (PER-15248).

``test_trigger_debounce.py`` covers the same coalescing behaviour end-to-end through the real
app; this module drives the state machine directly - no FastAPI, no OpalClient, no TestClient -
so the concurrency-shaped cases (a burst arriving mid-dispatch, the trailing edge, cancellation)
can be sequenced deterministically with ``asyncio.Event``s instead of hoping real requests
interleave the right way. It is also where the pure helper ``clamp_window`` is pinned.

TIME IS FAKED, NEVER SLEPT. The debouncer reads the clock as ``time.monotonic()`` via the module
global ``horizon.debounce.time``, so the ``clock`` fixture swaps that whole module reference for
a fake. Patching ``time.monotonic`` itself would be patching the *stdlib* function - which is
also the asyncio event loop's clock (``BaseEventLoop.time`` calls it) - and a frozen or rewound
loop clock would break every ``asyncio.wait_for`` timeout below.

Every test that leaves a dispatch parked inside ``run`` cancels its task in a ``finally``: an
assertion failing mid-test must not leak a task that outlives it (which shows up later as an
unrelated "Task was destroyed but it is pending" against whichever test runs next).
"""

import asyncio
import math
from collections.abc import Awaitable, Callable, Iterator

import pytest
from horizon import debounce
from horizon.debounce import MAX_DEBOUNCE_SECONDS, DebouncedTrigger, clamp_window
from loguru import logger

# Long enough that a real elapsed-time race can never make a "within the window" case flake;
# the fake clock means nothing actually waits for it.
WINDOW = 10.0
# Timeout for every "the other task should have reached this point by now" wait. Generous
# because it only bounds a hang: on the happy path these resolve on the next loop iteration.
TIMEOUT = 2.0


class FakeClock:
    """Stand-in for the ``time`` module as ``horizon.debounce`` uses it (only ``monotonic``).

    Starts well above zero so a test can never accidentally pass because ``_last_dispatched``
    happened to look like the ``None`` sentinel or like "the epoch".
    """

    def __init__(self, now: float = 1_000.0) -> None:
        self._now = now

    def monotonic(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(debounce, "time", fake)
    return fake


async def trigger_promptly(trigger: DebouncedTrigger, run: Callable[[], Awaitable[None]], window_seconds: float):
    """Issue a trigger that is expected to be coalesced, bounded by ``TIMEOUT``.

    The bound is part of the contract, not just hygiene: a coalesced trigger is documented to
    be an immediate no-op success that does NOT await the reload it collapsed into. It is also
    what keeps a regression in the guards *failing* instead of *hanging*. A trigger that should
    have been coalesced but instead runs ``run`` parks on the same event the in-flight dispatch
    is already parked on and never returns - and with no pytest-timeout plugin in this repo,
    a bare ``await`` there hangs the whole suite instead of reporting a failure.
    """
    return await asyncio.wait_for(trigger.trigger(run=run, window_seconds=window_seconds), timeout=TIMEOUT)


@pytest.fixture
def captured_logs() -> Iterator[list[tuple[str, str]]]:
    """``(level name, formatted message)`` for every loguru record emitted during the test."""
    records: list[tuple[str, str]] = []
    sink_id = logger.add(
        lambda message: records.append((message.record["level"].name, message.record["message"])),
        level="DEBUG",
    )
    yield records
    logger.remove(sink_id)


# --- clamp_window: the guard against a fat-fingered remote-config override ----------------


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        (-1.0, 0.0),  # negative == disabled, not "always coalesce"
        (0.0, 0.0),
        (0.5, 0.5),
        (WINDOW, WINDOW),
        (MAX_DEBOUNCE_SECONDS, MAX_DEBOUNCE_SECONDS),  # the cap itself is honoured, not clamped off
        (MAX_DEBOUNCE_SECONDS + 1, MAX_DEBOUNCE_SECONDS),
        (600_000.0, MAX_DEBOUNCE_SECONDS),  # the stray-zeroes override the cap exists for
        (math.inf, 0.0),  # non-finite collapses to "disabled"...
        (-math.inf, 0.0),
        (math.nan, 0.0),  # ...rather than making every comparison silently false
    ],
)
def test_clamp_window(configured: float, expected: float):
    assert clamp_window(configured) == expected


@pytest.mark.asyncio
async def test_window_is_clamped_inside_trigger(clock: FakeClock):
    """The clamp is applied per call, so an out-of-range config cannot wedge the debouncer."""
    trigger = DebouncedTrigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    huge = 600_000.0
    assert await trigger.trigger(run=run, window_seconds=huge) is True

    clock.advance(MAX_DEBOUNCE_SECONDS - 1)
    assert await trigger.trigger(run=run, window_seconds=huge) is False

    # Past the CAP - not past the configured 600000s - the next trigger fires again.
    clock.advance(2.0)
    assert await trigger.trigger(run=run, window_seconds=huge) is True
    assert calls == 2


# --- the window guard, and what the return value means ------------------------------------


@pytest.mark.asyncio
async def test_returns_true_when_dispatched_and_false_when_coalesced(clock: FakeClock):
    trigger = DebouncedTrigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    assert calls == 1

    clock.advance(WINDOW - 0.001)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False
    assert calls == 1

    # Boundary: the guard is `elapsed < window`, so at exactly one window the trigger fires.
    clock.advance(0.001)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    assert calls == 2


@pytest.mark.asyncio
async def test_window_is_consumed_by_the_dispatch_not_by_the_reload_succeeding(clock: FakeClock):
    """``_last_dispatched`` is a DISPATCH timestamp - there is no "only on success" guarantee.

    Both real updaters are fire-and-forget: ``trigger_update_policy`` is a queue put, and
    ``get_base_policy_data`` hands the per-entry fetches to a task pool. ``run`` returning
    therefore means "handed off", and a reload that fails afterwards in a background task is
    invisible from here - so it still consumes the window. The only failure this layer can
    observe is one raised out of ``run`` itself (see the cancellation/raise tests below).
    """
    trigger = DebouncedTrigger("data")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1
        # Stands in for the real hand-off: returns immediately, whatever happens next.

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    assert trigger._last_dispatched is not None

    clock.advance(1.0)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False
    assert calls == 1


@pytest.mark.asyncio
async def test_zero_window_lets_every_sequential_trigger_through():
    # No `clock` fixture: with the window disabled the guard never reads the clock at all.
    trigger = DebouncedTrigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    for _ in range(3):
        assert await trigger.trigger(run=run, window_seconds=0) is True
    assert calls == 3


# --- the in-flight guard, which is unconditional -------------------------------------------


@pytest.mark.asyncio
async def test_in_flight_guard_applies_even_with_the_window_disabled():
    """``window_seconds=0`` disables the TIME guard only.

    "No time-based damping" must never mean "two concurrent full pulls", so the in-flight guard
    is checked before - and independently of - the window. This is the case the pre-rewrite code
    got wrong: it returned early on ``window_seconds <= 0`` and bypassed the guard entirely.
    """
    trigger = DebouncedTrigger("policy")
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def run() -> None:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()

    dispatch = asyncio.create_task(trigger.trigger(run=run, window_seconds=0))
    try:
        await asyncio.wait_for(started.wait(), timeout=TIMEOUT)
        assert await trigger_promptly(trigger, run, window_seconds=0) is False
        assert calls == 1

        release.set()
        assert await asyncio.wait_for(dispatch, timeout=TIMEOUT) is True
    finally:
        release.set()
        if not dispatch.done():
            dispatch.cancel()

    # The coalesced trigger armed the trailing edge, so it was honoured rather than dropped.
    assert calls == 2


@pytest.mark.asyncio
async def test_concurrent_burst_collapses_into_a_single_dispatch():
    """The load-amplification case: N simultaneous triggers must not become N control-plane pulls."""
    trigger = DebouncedTrigger("data")
    calls = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def run() -> None:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()

    burst = asyncio.gather(*(trigger.trigger(run=run, window_seconds=0) for _ in range(5)))
    try:
        await asyncio.wait_for(started.wait(), timeout=TIMEOUT)
        # By the time the first dispatch has parked inside `run`, the other four have already
        # run and been coalesced behind the in-flight guard.
        assert calls == 1

        release.set()
        results = await asyncio.wait_for(burst, timeout=TIMEOUT)
    finally:
        release.set()
        if not burst.done():
            burst.cancel()

    assert results.count(True) == 1, f"exactly one call should report a dispatch, got {results}"
    assert results.count(False) == 4, f"the other four should report a coalesce, got {results}"
    # Two dispatches, not five: the original plus the single trailing edge covering all four
    # absorbed triggers.
    assert calls == 2


# --- the trailing edge ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trailing_edge_fires_exactly_once_and_is_not_re_armed():
    """Triggers absorbed in flight get ONE follow-up run, and that run cannot chain another.

    Without the trailing edge a trigger coalesced by the in-flight guard is simply lost: the
    reload it collapsed into may already have read its data before the caller's change landed.
    With an unbounded trailing edge, a sustained hammer would keep re-arming it and never let
    the dispatch finish. So: two runs per call, maximum.
    """
    trigger = DebouncedTrigger("policy")
    # Three slots so a (buggy) third run has somewhere to go and can be asserted against,
    # rather than blowing up with an IndexError that reads like an unrelated failure.
    entered = [asyncio.Event() for _ in range(3)]
    gates = [asyncio.Event() for _ in range(3)]
    calls = 0

    async def run() -> None:
        nonlocal calls
        index = calls
        calls += 1
        entered[index].set()
        await gates[index].wait()

    dispatch = asyncio.create_task(trigger.trigger(run=run, window_seconds=0))
    try:
        await asyncio.wait_for(entered[0].wait(), timeout=TIMEOUT)

        # Two triggers absorbed by the in-flight guard must produce ONE trailing run, not two.
        assert await trigger_promptly(trigger, run, window_seconds=0) is False
        assert await trigger_promptly(trigger, run, window_seconds=0) is False

        gates[0].set()
        await asyncio.wait_for(entered[1].wait(), timeout=TIMEOUT)
        assert calls == 2

        # A trigger arriving during the TRAILING run is still coalesced (the guard is on
        # `_in_flight`, which is still set) but the trailing edge is spent, so it must not
        # schedule a further run - staleness from here is bounded by the window guard.
        assert await trigger_promptly(trigger, run, window_seconds=0) is False

        gates[1].set()
        assert await asyncio.wait_for(dispatch, timeout=TIMEOUT) is True
    finally:
        for gate in gates:
            gate.set()
        if not dispatch.done():
            dispatch.cancel()

    assert calls == 2
    assert not entered[2].is_set(), "the trailing edge re-armed itself; dispatches are not capped at two"


@pytest.mark.asyncio
async def test_no_trailing_edge_when_nothing_arrived_mid_dispatch():
    trigger = DebouncedTrigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1
        # A real suspension point, so a concurrent trigger *could* have interleaved here.
        # Nothing does, so the trailing edge must stay disarmed.
        await asyncio.sleep(0)

    assert await trigger.trigger(run=run, window_seconds=0) is True
    assert calls == 1
    assert trigger._pending is False
    assert trigger._in_flight is False


# --- failure paths: the guards must never wedge --------------------------------------------


@pytest.mark.asyncio
async def test_cancelling_a_dispatch_resets_in_flight_and_records_no_dispatch():
    """A cancelled dispatch (client disconnect, shutdown) must not leave the guard stuck on.

    ``_in_flight`` is cleared by the ``finally``; ``_last_dispatched`` is assigned only after
    ``await run()`` *returns*, which cancellation prevents. So the debouncer is left exactly as
    it was before the call, and ``CancelledError`` still propagates to the caller.
    """
    trigger = DebouncedTrigger("data")
    started = asyncio.Event()
    never = asyncio.Event()

    async def run() -> None:
        started.set()
        await never.wait()  # only cancellation ends this

    dispatch = asyncio.create_task(trigger.trigger(run=run, window_seconds=0))
    try:
        await asyncio.wait_for(started.wait(), timeout=TIMEOUT)
    finally:
        dispatch.cancel()

    with pytest.raises(asyncio.CancelledError):
        await dispatch

    assert trigger._in_flight is False
    assert trigger._last_dispatched is None
    assert trigger._pending is False

    # Not wedged: the next trigger dispatches instead of coalescing forever.
    calls = 0

    async def run_again() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run_again, window_seconds=WINDOW) is True
    assert calls == 1


@pytest.mark.asyncio
async def test_a_run_that_raises_propagates_and_records_no_dispatch():
    # No `clock` fixture: nothing here needs time to move, which is precisely the point - the
    # retry below is admitted because no dispatch was ever recorded, not because time passed.
    trigger = DebouncedTrigger("data")

    async def boom() -> None:
        raise RuntimeError("dispatch failed")

    with pytest.raises(RuntimeError, match="dispatch failed"):
        await trigger.trigger(run=boom, window_seconds=WINDOW)

    assert trigger._last_dispatched is None
    assert trigger._in_flight is False

    # ...so an immediate retry inside the window is NOT coalesced.
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    assert calls == 1


# --- logging: the mitigation must not amplify log volume -----------------------------------


@pytest.mark.asyncio
async def test_coalesce_logging_is_loud_once_then_quiet(clock: FakeClock, captured_logs: list[tuple[str, str]]):
    """Under the exact hammering this class absorbs, one INFO per suppressed request would just
    move the amplification from the control plane to the (unbounded, enqueue=True) log sink."""
    trigger = DebouncedTrigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    for _ in range(3):
        assert await trigger.trigger(run=run, window_seconds=WINDOW) is False

    coalesce_levels = [level for level, message in captured_logs if message.startswith("Coalescing")]
    assert coalesce_levels == ["INFO", "DEBUG", "DEBUG"]

    # The DEBUG lines are not a blind spot: the next dispatch reports the absorbed total.
    clock.advance(WINDOW + 1)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    assert calls == 2
    assert ("INFO", "Dispatched policy reload, absorbing 3 coalesced trigger(s).") in captured_logs

    # ...and the counter resets, so the next burst is reported on its own terms.
    assert trigger._coalesced == 0

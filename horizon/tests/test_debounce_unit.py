"""Unit tests for :class:`horizon.debounce.DebouncedTrigger` (PER-15248).

``test_trigger_debounce.py`` covers the same coalescing behaviour end-to-end through the real
app; this module drives the state machine directly - no FastAPI, no OpalClient, no TestClient -
so the concurrency-shaped cases (a burst arriving mid-dispatch, the trailing edge, cancellation)
can be sequenced deterministically with ``asyncio.Event``s instead of hoping real requests
interleave the right way. It is also where the pure helpers ``resolve_window`` / ``clamp_window``
are pinned.

TIME IS FAKED, NEVER SLEPT - in two places that must stay coherent with each other:

* the debouncer reads the clock as ``time.monotonic()`` via the module global
  ``horizon.debounce.time``, so the ``clock`` fixture swaps that whole module reference for a
  fake. Patching ``time.monotonic`` itself would be patching the *stdlib* function - which is
  also the asyncio event loop's clock (``BaseEventLoop.time`` calls it) - and a frozen or
  rewound loop clock would break every ``asyncio.wait_for`` timeout below.
* the trailing edge waits out the debounce window via the module global
  ``horizon.debounce._sleep``, so the ``sleeper`` fixture swaps that for a fake that ADVANCES
  the clock by the requested delay instead of waiting. Advancing is not a nicety: the debouncer
  re-stamps ``_last_dispatched`` from the (fake) clock after the trailing run, so a sleep that
  returned without moving time would leave every later window assertion off by the delay.

TRAILING RUNS ARE TASKS, so a test that arms one must also drain it - ``drain_trailing`` - or
assert deliberately that it is still armed. Every trigger is built through the ``make_trigger``
factory, whose teardown calls the production ``aclose()``; that keeps an assertion failing
mid-test from leaking a task into whichever test runs next (as an unrelated "Task was destroyed
but it is pending"), and doubles as coverage of the shutdown path.

Every test that leaves a dispatch parked inside ``run`` also cancels its own task in a
``finally``, for the same reason.
"""

import asyncio
import math
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator

import pytest
import pytest_asyncio
from horizon import debounce
from horizon.debounce import (
    DEFAULT_DEBOUNCE_SECONDS,
    MAX_DEBOUNCE_SECONDS,
    MAX_DISPATCH_SECONDS,
    DebouncedTrigger,
    clamp_window,
    resolve_window,
)
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


class FakeSleep:
    """Stand-in for ``horizon.debounce._sleep``: records the delay and advances the clock by it.

    Returns without waiting, but still yields to the event loop once, so a trailing run cannot
    quietly become synchronous and hide an ordering bug that real time would expose.
    """

    def __init__(self, clock: FakeClock) -> None:
        self._clock = clock
        self.requested: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.requested.append(seconds)
        self._clock.advance(seconds)
        await asyncio.sleep(0)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(debounce, "time", fake)
    return fake


@pytest.fixture
def sleeper(clock: FakeClock, monkeypatch: pytest.MonkeyPatch) -> FakeSleep:
    fake = FakeSleep(clock)
    monkeypatch.setattr(debounce, "_sleep", fake)
    return fake


@pytest_asyncio.fixture
async def make_trigger() -> AsyncIterator[Callable[[str], DebouncedTrigger]]:
    """Build ``DebouncedTrigger``s that are guaranteed to be closed down at teardown.

    Uses the production ``aclose()``, so every test in this module is also a small exercise of
    the shutdown path wired up in ``PermitPDP._configure_trigger_routes``.
    """
    created: list[DebouncedTrigger] = []

    def factory(name: str) -> DebouncedTrigger:
        trigger = DebouncedTrigger(name)
        created.append(trigger)
        return trigger

    yield factory
    for trigger in created:
        await trigger.aclose()


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


async def drain_trailing(trigger: DebouncedTrigger) -> None:
    """Run every armed (and chained) trailing task to completion, bounded by ``TIMEOUT``.

    Loops because a trailing run re-arms when triggers arrived while it was running. It
    terminates for the same reason the production chain does: nothing here sets ``_pending``.
    """
    while (task := trigger._trailing_task) is not None:
        await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), timeout=TIMEOUT)


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


# --- resolve_window / clamp_window: the guard against a fat-fingered remote-config override ---


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        # An explicit, parseable 0 is the ONLY way to disable the window.
        (0.0, 0.0),
        (0, 0.0),
        (0.5, 0.5),
        (WINDOW, WINDOW),
        # confi's cast_from_json is no_cast, so a remote override arrives VERBATIM - a numeric
        # string is a perfectly valid override and must be honoured, not treated as garbage.
        ("30", 30.0),
        (MAX_DEBOUNCE_SECONDS, MAX_DEBOUNCE_SECONDS),  # the cap itself is honoured, not clamped off
        (MAX_DEBOUNCE_SECONDS + 1, MAX_DEBOUNCE_SECONDS),
        (600_000.0, MAX_DEBOUNCE_SECONDS),  # the stray-zeroes override the cap exists for
        # Everything uninterpretable falls back to the DEFAULT, not to 0. Failing open here
        # would mean one control-plane typo silently switches the mitigation off fleet-wide -
        # the opposite of what a protection knob should do when it cannot be read.
        (-1.0, DEFAULT_DEBOUNCE_SECONDS),  # a negative is a typo, not a request to disable
        (math.inf, DEFAULT_DEBOUNCE_SECONDS),
        (-math.inf, DEFAULT_DEBOUNCE_SECONDS),
        (math.nan, DEFAULT_DEBOUNCE_SECONDS),  # ...and never a value that makes every comparison false
        (None, DEFAULT_DEBOUNCE_SECONDS),  # a remote-config `null`
        ("", DEFAULT_DEBOUNCE_SECONDS),
        ("tem", DEFAULT_DEBOUNCE_SECONDS),  # a fat-fingered "ten"
    ],
)
def test_clamp_window(configured: object, expected: float):
    assert clamp_window(configured) == expected


@pytest.mark.parametrize(
    ("configured", "expected_window", "expected_problem"),
    [
        (WINDOW, WINDOW, None),
        (0.0, 0.0, None),
        (30, 30.0, None),
        # The regression this reporting exists for: comparing the coerced float against the raw
        # attribute made a VALID override delivered as the JSON string "30" look like a clamp,
        # and logged "out of range; clamped to 30s" - false on both counts.
        ("30", 30.0, None),
        (600_000.0, MAX_DEBOUNCE_SECONDS, "clamped"),
        (MAX_DEBOUNCE_SECONDS + 1, MAX_DEBOUNCE_SECONDS, "clamped"),
        (-1.0, DEFAULT_DEBOUNCE_SECONDS, "unparseable"),
        (None, DEFAULT_DEBOUNCE_SECONDS, "unparseable"),
        ("tem", DEFAULT_DEBOUNCE_SECONDS, "unparseable"),
        (math.nan, DEFAULT_DEBOUNCE_SECONDS, "unparseable"),
    ],
)
def test_resolve_window_reports_why_the_value_changed(
    configured: object, expected_window: float, expected_problem: str | None
):
    """The caller logs a different message and severity per case, so the reason has to survive."""
    assert resolve_window(configured) == (expected_window, expected_problem)


def test_resolve_window_honours_an_explicit_default():
    assert resolve_window("nonsense", default=42.0) == (42.0, "unparseable")


@pytest.mark.asyncio
async def test_window_is_clamped_inside_trigger(clock: FakeClock, sleeper: FakeSleep, make_trigger):
    """The clamp is applied per call, so an out-of-range config cannot wedge the debouncer."""
    trigger = make_trigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    huge = 600_000.0
    assert await trigger.trigger(run=run, window_seconds=huge) is True

    clock.advance(MAX_DEBOUNCE_SECONDS - 1)
    assert await trigger.trigger(run=run, window_seconds=huge) is False

    # The trailing run waits out the remainder of the CAP - one second - not the remainder of
    # the configured 600000s, which is what an unclamped window would have parked on.
    await drain_trailing(trigger)
    assert sleeper.requested == [1.0]
    assert calls == 2


# --- the window guard, and what the return value means ------------------------------------


@pytest.mark.asyncio
async def test_returns_true_when_dispatched_and_false_when_coalesced(
    clock: FakeClock, sleeper: FakeSleep, make_trigger
):
    trigger = make_trigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    assert calls == 1

    clock.advance(WINDOW - 0.001)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False
    assert calls == 1

    # The coalesced trigger is served by the trailing run, not dropped.
    await drain_trailing(trigger)
    assert sleeper.requested == [pytest.approx(0.001)]
    assert calls == 2

    # Boundary: the guard is `elapsed < window`, so at exactly one window the trigger fires.
    clock.advance(WINDOW)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    assert calls == 3


@pytest.mark.asyncio
async def test_window_coalesced_trigger_is_served_by_a_trailing_run(clock: FakeClock, sleeper: FakeSleep, make_trigger):
    """The headline semantic: a window-coalesced trigger is DEFERRED, never discarded.

    The dispatch it collapsed into already read the control plane before this caller's change
    landed, and the PDP is pubsub-driven with no periodic full-refresh cadence - so dropping it
    would lose the refresh permanently, which is what PER-15248 forbids. The endpoint tells
    clients "do not retry on `triggered: false`", and this is the mechanism that makes that
    instruction safe to follow.
    """
    trigger = make_trigger("data")
    reasons: list[str] = []

    async def run_first() -> None:
        reasons.append("first")

    async def run_coalesced() -> None:
        reasons.append("coalesced")

    assert await trigger.trigger(run=run_first, window_seconds=WINDOW) is True

    clock.advance(2.0)
    assert await trigger.trigger(run=run_coalesced, window_seconds=WINDOW) is False
    assert trigger._trailing_task is not None, "a window-coalesced trigger must arm a trailing run"
    assert reasons == ["first"], "the trailing run must not start before the window expires"

    await drain_trailing(trigger)
    # It waited out the REMAINDER of the window (8s of 10), and it ran the coalesced caller's
    # own closure rather than re-running the original.
    assert sleeper.requested == [pytest.approx(8.0)]
    assert reasons == ["first", "coalesced"]
    # ...and the chain stops, because nothing arrived while it was running.
    assert trigger._trailing_task is None
    assert trigger._pending is False


@pytest.mark.asyncio
@pytest.mark.usefixtures("sleeper")
async def test_guard_one_coalesces_while_a_trailing_run_is_armed_even_past_the_window(clock: FakeClock, make_trigger):
    """An armed trailing run accounts for later triggers, so they must not start a second pull.

    Without ``_trailing_task`` in guard 1 a trigger arriving after the window elapsed - but
    before the armed trailing run fires - would dispatch concurrently with it.
    """
    trigger = make_trigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    clock.advance(1.0)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False  # arms the trailing run
    assert trigger._trailing_task is not None

    # Jump the clock clean past the window: the window guard alone would now ADMIT.
    clock.advance(WINDOW * 5)
    # Awaited DIRECTLY rather than through `trigger_promptly`: the coalesce path contains no
    # `await`, so this never yields, and the armed trailing task has still not had a single
    # step. Routing it through `wait_for` would hand the loop over and let the trailing run
    # finish first, quietly turning this into a test of the window guard instead.
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False
    assert calls == 1, "only guard 1 can account for this coalesce"

    await drain_trailing(trigger)
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.usefixtures("sleeper")
async def test_window_is_consumed_by_the_dispatch_not_by_the_reload_succeeding(clock: FakeClock, make_trigger):
    """``_last_dispatched`` is a DISPATCH timestamp - it never waits on the reload succeeding.

    Both real updaters are fire-and-forget: ``trigger_update_policy`` is a queue put, and
    ``get_base_policy_data`` hands the per-entry fetches to a task pool. ``run`` returning
    therefore means "handed off", and a reload that fails afterwards in a background task is
    invisible from here - so it still consumes the window. See
    ``test_a_run_that_raises_consumes_the_window`` for the failure this layer CAN observe.
    """
    trigger = make_trigger("data")
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

    await drain_trailing(trigger)
    assert calls == 2


@pytest.mark.asyncio
async def test_zero_window_lets_every_sequential_trigger_through(make_trigger):
    # No `clock` fixture: with the window disabled the guard never reads the clock at all.
    trigger = make_trigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    for _ in range(3):
        assert await trigger.trigger(run=run, window_seconds=0) is True
    assert calls == 3
    # Nothing was ever coalesced, so no trailing run was armed.
    assert trigger._trailing_task is None
    assert trigger._pending is False


# --- the in-flight guard, which is unconditional -------------------------------------------


@pytest.mark.asyncio
async def test_in_flight_guard_applies_even_with_the_window_disabled(make_trigger):
    """``window_seconds=0`` disables the TIME guard only.

    "No time-based damping" must never mean "two concurrent full pulls", so the in-flight guard
    is checked before - and independently of - the window. This is the case the pre-rewrite code
    got wrong: it returned early on ``window_seconds <= 0`` and bypassed the guard entirely.
    """
    trigger = make_trigger("policy")
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

    # The coalesced trigger armed the trailing edge, so it is honoured rather than dropped -
    # but off the request path, so the dispatching caller was not billed for it.
    await drain_trailing(trigger)
    assert calls == 2


@pytest.mark.asyncio
async def test_concurrent_burst_collapses_into_a_single_dispatch(make_trigger):
    """The load-amplification case: N simultaneous triggers must not become N control-plane pulls."""
    trigger = make_trigger("data")
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
    await drain_trailing(trigger)
    assert calls == 2


# --- the trailing edge ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trailing_run_is_not_awaited_by_the_dispatching_caller(make_trigger):
    """The dispatching caller must not be billed for a reload somebody else's trigger asked for.

    It used to await the trailing run inline, doubling that request's worst-case latency against
    the 60s client timeout of the Rust server that fronts this app - so a caller could be timed
    out at the proxy for work it never requested, then retry, feeding the very amplification
    loop this class exists to break.
    """
    trigger = make_trigger("policy")
    entered = [asyncio.Event() for _ in range(2)]
    gates = [asyncio.Event() for _ in range(2)]
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
        assert await trigger_promptly(trigger, run, window_seconds=0) is False

        # Release only the FIRST run. If the trailing run were still inline, the dispatching
        # call would now park on gates[1] and this wait_for would time out.
        gates[0].set()
        assert await asyncio.wait_for(dispatch, timeout=TIMEOUT) is True

        # It returned while the trailing run is still parked inside `run` - i.e. genuinely off
        # the request path.
        await asyncio.wait_for(entered[1].wait(), timeout=TIMEOUT)
        assert trigger._trailing_task is not None
        gates[1].set()
    finally:
        for gate in gates:
            gate.set()
        if not dispatch.done():
            dispatch.cancel()

    await drain_trailing(trigger)
    assert calls == 2


@pytest.mark.asyncio
async def test_trailing_edge_chains_while_triggers_keep_arriving_then_stops(make_trigger):
    """A trigger arriving during a trailing run gets its own follow-up - and the chain terminates.

    ``_pending`` is written ``True`` in exactly one place (``trigger``, by an external caller)
    and nothing in the trailing path sets it, so chain length is bounded by the number of real
    triggers. That is what stops this from degenerating into a standing one-reload-per-window
    load on the control plane with no client asking for anything.
    """
    trigger = make_trigger("policy")
    # Four slots so a (buggy) fourth run has somewhere to go and can be asserted against,
    # rather than blowing up with an IndexError that reads like an unrelated failure.
    entered = [asyncio.Event() for _ in range(4)]
    gates = [asyncio.Event() for _ in range(4)]
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
        assert await asyncio.wait_for(dispatch, timeout=TIMEOUT) is True
        await asyncio.wait_for(entered[1].wait(), timeout=TIMEOUT)
        assert calls == 2

        # A trigger arriving DURING the trailing run is coalesced (guard 1 - `_in_flight` is set
        # again for the trailing run) and chains exactly one more run, so it is not dropped.
        assert await trigger_promptly(trigger, run, window_seconds=0) is False
        gates[1].set()
        await asyncio.wait_for(entered[2].wait(), timeout=TIMEOUT)
        assert calls == 3

        gates[2].set()
    finally:
        for gate in gates:
            gate.set()
        if not dispatch.done():
            dispatch.cancel()

    await drain_trailing(trigger)
    # ...and now it stops: nothing arrived during the third run, so nothing re-armed.
    assert calls == 3
    assert not entered[3].is_set(), "the chain re-armed with no trigger to justify it"
    assert trigger._trailing_task is None
    assert trigger._pending is False


@pytest.mark.asyncio
async def test_no_trailing_edge_when_nothing_arrived_mid_dispatch(make_trigger):
    trigger = make_trigger("policy")
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
    assert trigger._trailing_task is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("sleeper")
async def test_a_trailing_run_that_raises_clears_the_handle(clock: FakeClock, make_trigger):
    """A failing trailing run must not wedge the debouncer into coalescing forever.

    ``_trailing_task`` is half of guard 1, so leaving it set after a failure would make every
    future trigger a no-op - the exact failure this class exists to prevent.
    """
    trigger = make_trigger("data")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1
        if calls == 2:  # the trailing run
            raise RuntimeError("trailing boom")

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    clock.advance(1.0)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False

    await drain_trailing(trigger)
    assert calls == 2
    # Not wedged, and the failed attempt still consumed the window.
    assert trigger._trailing_task is None
    assert trigger._in_flight is False
    assert trigger._last_dispatched is not None

    clock.advance(WINDOW + 1)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    assert calls == 3


@pytest.mark.asyncio
@pytest.mark.usefixtures("sleeper")
async def test_a_trailing_task_cancelled_before_its_first_step_clears_the_handle(clock: FakeClock, make_trigger):
    """The case ``_run_trailing``'s own ``finally`` cannot cover, hence the done-callback.

    A task cancelled before it is ever scheduled never runs its body at all, so nothing inside
    the coroutine can clear ``_trailing_task`` - and a permanently-set handle coalesces every
    future trigger.
    """
    trigger = make_trigger("policy")

    async def run() -> None:
        pass

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    clock.advance(1.0)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False

    task = trigger._trailing_task
    assert task is not None
    # Cancel before the loop has ever given it a step: the coalesce path above returns without
    # suspending, so the task has not started.
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    assert trigger._trailing_task is None
    # ...and the debouncer still works.
    clock.advance(WINDOW + 1)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True


@pytest.mark.asyncio
@pytest.mark.usefixtures("sleeper")
async def test_aclose_cancels_an_armed_trailing_run_and_is_idempotent(clock: FakeClock, make_trigger):
    """Shutdown must not leave a trailing reload outliving the event loop."""
    trigger = make_trigger("data")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    clock.advance(1.0)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False
    assert trigger._trailing_task is not None

    await trigger.aclose()
    assert trigger._trailing_task is None
    assert calls == 1, "the trailing run was cancelled before it could dispatch"

    # Idempotent: closing again with nothing armed is a no-op, not an error.
    await trigger.aclose()


# --- failure paths: the guards must never wedge --------------------------------------------


@pytest.mark.asyncio
async def test_cancelling_a_dispatch_resets_in_flight_and_records_no_dispatch(make_trigger):
    """A cancelled dispatch (client disconnect, shutdown) must not leave the guard stuck on.

    Cancellation is the one case that does NOT consume the window: the attempt was abandoned
    rather than made, so the control plane was not necessarily asked. The debouncer is left
    exactly as it was before the call, and ``CancelledError`` still propagates to the caller.
    """
    trigger = make_trigger("data")
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
    # Nothing was coalesced into it, and on shutdown there would be nobody left to run one.
    assert trigger._trailing_task is None

    # Not wedged: the next trigger dispatches instead of coalescing forever.
    calls = 0

    async def run_again() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run_again, window_seconds=WINDOW) is True
    assert calls == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("sleeper")
async def test_a_run_that_raises_consumes_the_window(clock: FakeClock, make_trigger):
    """A FAILED dispatch damps the next one just as a successful dispatch does.

    This is the whole point of stamping ``_last_dispatched`` in a ``finally``. ``run`` for the
    data route reaches ``get_policy_data_config``, which raises ``ClientError`` on any non-200
    from the control plane - so a window consumed only by SUCCESSES would leave the mitigation
    switched off in exactly the degraded-control-plane conditions it exists for, letting one
    retrying client sustain a fresh control-plane GET per request.
    """
    trigger = make_trigger("data")

    async def boom() -> None:
        raise RuntimeError("dispatch failed")

    with pytest.raises(RuntimeError, match="dispatch failed"):
        await trigger.trigger(run=boom, window_seconds=WINDOW)

    assert trigger._last_dispatched is not None, "the ATTEMPT consumes the window, not the outcome"
    assert trigger._in_flight is False
    assert trigger._trailing_task is None, "nothing was coalesced into it, so nothing to re-run"

    # An immediate retry inside the window is therefore coalesced - no second pull...
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    clock.advance(1.0)
    assert await trigger.trigger(run=run, window_seconds=WINDOW) is False
    assert calls == 0

    # ...and it is still not dropped: the trailing run retries once the window expires.
    await drain_trailing(trigger)
    assert calls == 1


# --- observability: a stalled dispatch must not be silent ----------------------------------


@pytest.mark.asyncio
@pytest.mark.usefixtures("sleeper")
async def test_a_stalled_dispatch_escalates_the_coalesce_log_to_error(
    clock: FakeClock, make_trigger, captured_logs: list[tuple[str, str]]
):
    """``run`` is never cancelled, so a hung control-plane GET can hold guard 1 for minutes.

    Cancelling it is not an option - ``get_base_policy_data`` tears down every periodic poller
    BEFORE the config GET and only recreates them at the very end, so a timeout landing on the
    stalled GET would kill periodic data updates outright. The stall is made loud instead.
    """
    trigger = make_trigger("data")
    started = asyncio.Event()
    release = asyncio.Event()

    async def run() -> None:
        started.set()
        await release.wait()

    dispatch = asyncio.create_task(trigger.trigger(run=run, window_seconds=WINDOW))
    try:
        await asyncio.wait_for(started.wait(), timeout=TIMEOUT)

        # A dispatch that is merely slow stays at INFO...
        assert await trigger_promptly(trigger, run, window_seconds=WINDOW) is False

        # ...but once it is stalled, every coalesce is alertable rather than buried at DEBUG.
        clock.advance(MAX_DISPATCH_SECONDS + 1)
        for _ in range(2):
            assert await trigger_promptly(trigger, run, window_seconds=WINDOW) is False

        release.set()
        await asyncio.wait_for(dispatch, timeout=TIMEOUT)
    finally:
        release.set()
        if not dispatch.done():
            dispatch.cancel()

    await drain_trailing(trigger)

    coalesce_levels = [level for level, message in captured_logs if message.startswith("Coalescing")]
    assert coalesce_levels == ["INFO", "ERROR", "ERROR"]
    assert any("control plane looks stalled" in message for _, message in captured_logs)


# --- logging: the mitigation must not amplify log volume -----------------------------------


@pytest.mark.asyncio
@pytest.mark.usefixtures("sleeper")
async def test_coalesce_logging_is_loud_once_then_quiet(make_trigger, captured_logs: list[tuple[str, str]]):
    """Under the exact hammering this class absorbs, one INFO per suppressed request would just
    move the amplification from the control plane to the (unbounded, enqueue=True) log sink."""
    trigger = make_trigger("policy")
    calls = 0

    async def run() -> None:
        nonlocal calls
        calls += 1

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    for _ in range(3):
        assert await trigger.trigger(run=run, window_seconds=WINDOW) is False

    coalesce_levels = [level for level, message in captured_logs if message.startswith("Coalescing")]
    assert coalesce_levels == ["INFO", "DEBUG", "DEBUG"]

    # The DEBUG lines are not a blind spot: the trailing run reports the absorbed total when it
    # serves them.
    await drain_trailing(trigger)
    assert calls == 2
    assert ("INFO", "Dispatched policy reload, absorbing 3 coalesced trigger(s).") in captured_logs

    # ...and the counter resets, so the next burst is reported on its own terms.
    assert trigger._coalesced == 0


@pytest.mark.asyncio
async def test_aclose_during_the_trailing_wait_does_not_arm_a_replacement(clock: FakeClock, make_trigger):
    """Cancelling a trailing run that is still waiting out the window must end the chain.

    This is the common shutdown shape: ``aclose`` almost always finds the trailing task parked
    in ``_sleep`` rather than mid-dispatch, and ``_pending`` is still set there (it is cleared
    only once the wait is over). A re-arm at that point would create a task during loop
    teardown - after the cancel-all sweep has already run - which is precisely the
    "Task was destroyed but it is pending" that arming a background task has to avoid.
    """
    trigger = make_trigger("data")
    waiting = asyncio.Event()

    async def never_finishes_waiting(_seconds: float) -> None:
        waiting.set()
        await asyncio.Event().wait()  # only cancellation ends this

    async def run() -> None:
        pass

    assert await trigger.trigger(run=run, window_seconds=WINDOW) is True
    clock.advance(1.0)

    # Patch the sleep only now, so the dispatch above is unaffected.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(debounce, "_sleep", never_finishes_waiting)
        assert await trigger.trigger(run=run, window_seconds=WINDOW) is False
        await asyncio.wait_for(waiting.wait(), timeout=TIMEOUT)
        assert trigger._pending is True, "the trigger is still unserved while the run waits"

        await trigger.aclose()

    assert trigger._trailing_task is None, "cancellation must not chain a replacement task"
    assert trigger._in_flight is False

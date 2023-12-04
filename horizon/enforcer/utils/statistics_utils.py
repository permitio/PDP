import asyncio

from loguru import logger


class StatisticsManager:
    def __init__(
        self, interval_seconds: int = 60, failures_threshold_percentage: float = 0.1
    ):
        self._requests = 0
        self._failures = 0
        self._messages: asyncio.Queue[bool] = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._restarter_task: asyncio.Task | None = None
        self._interval_task: asyncio.Task | None = None
        self._interval_seconds = interval_seconds
        self._failures_threshold_percentage = failures_threshold_percentage
        self._had_failure = False

    async def restarter_task(self) -> None:
        while True:
            message = await self._messages.get()
            try:
                async with self._lock:
                    logger.debug("Statistics message: {message}", message=message)
                    self._requests += 1
                    if message is False:
                        self._failures += 1
            finally:
                self._messages.task_done()

    async def reset_stats(self) -> None:
        async with self._lock:
            logger.debug(
                "Resetting error rate current status is requests={requests}, failures={failures}",
                requests=self._requests,
                failures=self._failures,
            )
            self._requests = 0
            self._failures = 0

    async def interval_task(self) -> None:
        while True:
            await asyncio.sleep(self._interval_seconds)
            await self.reset_stats()

    async def run(self) -> None:
        logger.debug("Starting statistics manager")
        if self._restarter_task is None:
            self._restarter_task = asyncio.create_task(self.restarter_task())
        if self._interval_task is None:
            self._interval_task = asyncio.create_task(self.interval_task())

    async def stop(self) -> None:
        logger.debug("Stopping statistics manager")
        await self._messages.join()
        if self._restarter_task is not None:
            self._restarter_task.cancel()
            self._restarter_task = None
        if self._interval_task is not None:
            self._interval_task.cancel()
            self._interval_task = None

    def report_success(self) -> None:
        logger.debug("Reporting success")
        self._messages.put_nowait(True)

    def report_failure(self) -> None:
        logger.debug("Reporting failure")
        self._messages.put_nowait(False)

    async def current_rate(self) -> float:
        current_requests, current_failures = float(self._requests), float(
            self._failures
        )
        if current_requests == 0:
            return 0.0
        return current_failures / current_requests

    async def status(self) -> bool:
        rate = await self.current_rate()
        if rate > self._failures_threshold_percentage:
            self._had_failure = True
        return self._had_failure

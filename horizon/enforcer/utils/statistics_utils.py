import asyncio


class StatisticsManager:
    def __init__(self, interval_seconds: int = 2 * 60):
        self._requests = 0
        self._failures = 0
        self._messages: asyncio.Queue[bool] = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._restarter_task = None
        self._interval_task = None
        self._interval_seconds = interval_seconds

    async def restarter_task(self) -> None:
        while True:
            message = await self._messages.get()
            try:
                async with self._lock:
                    self._requests += 1
                    if message is False:
                        self._failures += 1
            finally:
                self._messages.task_done()
            await asyncio.sleep(0.5)

    async def interval_task(self) -> None:
        while True:
            await asyncio.sleep(self._interval_seconds)
            async with self._lock:
                self._requests = 0
                self._failures = 0

    def run(self) -> None:
        self._restarter_task = asyncio.create_task(self.restarter_task())
        self._interval_task = asyncio.create_task(self._interval_task())

    def report_success(self) -> None:
        self._messages.put_nowait(True)

    def report_failure(self) -> None:
        self._messages.put_nowait(False)

    async def current_rate(self) -> float:
        async with self._lock:
            current_requests = float(self._requests)
            current_failures = float(self._failures)
        return current_failures / current_requests

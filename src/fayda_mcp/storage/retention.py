"""Scheduled retention cleanup manager for expired verification records.

Ensures expired requests and results are purged from durable storage outside
the critical request/response path.
"""

import asyncio
import logging
from typing import Optional
from fayda_mcp.storage.protocols import ResultRepository

logger = logging.getLogger("fayda_mcp.storage.retention")


class RetentionCleanupManager:
    """Manages scheduled background retention cleanup of expired requests and results."""

    def __init__(self, repository: ResultRepository) -> None:
        self.repository = repository
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def run_once(self) -> int:
        """Execute a single retention cleanup pass.

        Returns total count of purged expired records.
        """
        try:
            purged = await self.repository.cleanup()
            if purged > 0:
                logger.info("Purged %d expired verification records.", purged)
            return purged
        except Exception as e:
            logger.error("Retention cleanup pass failed: %s", e)
            raise

    async def _cleanup_loop(self, interval_seconds: float) -> None:
        """Background loop executing cleanup periodically."""
        while self._running:
            try:
                await self.run_once()
            except Exception as e:
                logger.warning("Error during periodic retention cleanup: %s", e)
            try:
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                break

    def start_periodic(self, interval_seconds: float = 300.0) -> asyncio.Task:
        """Start background periodic cleanup task."""
        if self._running and self._task and not self._task.done():
            return self._task

        self._running = True
        self._task = asyncio.create_task(
            self._cleanup_loop(interval_seconds),
            name="fayda_retention_cleanup",
        )
        return self._task

    async def stop(self) -> None:
        """Cleanly cancel and await termination of the background cleanup task."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

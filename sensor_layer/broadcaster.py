"""Sensor Broadcaster, streams compliance data to MCP Server

Runs as a systemd service, periodically scanning and broadcasting
compliance data to the central MCP server
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import signal
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from dotenv import load_dotenv

from .scanner import ComplianceScanner
from .log_tailer import AuditLogTailer

load_dotenv()
log = logging.getLogger(__name__)

MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8001")
SCAN_INTERVAL_SECONDS = int(os.getenv("SENSOR_SCAN_INTERVAL", "900"))  # 15 minutes
CRITICAL_CHECK_INTERVAL = int(os.getenv("SENSOR_CRITICAL_INTERVAL", "300"))  # 5 minute
SENSOR_API_KEY = os.getenv("SENSOR_API_KEY", "")
HOSTNAME = os.getenv("SENSOR_HOSTNAME", socket.gethostname())


@dataclass(slots=True)
class BroadcastResult:
    """Result of a broadcast operation."""

    success: bool
    timestamp: str
    message: str
    response_data: dict[str, Any] = field(default_factory=dict)


class SensorBroadcaster:
    """Broadcasts sensor data to MCP server."""

    def __init__(
        self,
        mcp_url: str = MCP_SERVER_URL,
        hostname: str = HOSTNAME,
        api_key: str = SENSOR_API_KEY,
    ):
        self.mcp_url = mcp_url.rstrip("/")
        self.hostname = hostname
        self.api_key = api_key
        self._mcp_endpoint = f"{self.mcp_url}/mcp"
        self.scanner = ComplianceScanner(hostname=hostname)
        self.log_tailer = AuditLogTailer()

        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=10.0),
            http2=True,
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=5),
            headers=self._build_headers(),
        )
        self._running = False
        self._last_scan_id: str | None = None
        self._req_id = 0

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for requests."""
        headers = {
            "Content-Type": "application/json",
            "X-Sensor-Hostname": self.hostname,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _mcp_payload(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Build JSON-RPC payload for MCP server."""
        self._req_id += 1
        return {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": method,
            "params": params,
        }

    async def _call_mcp_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Call an MCP tool via JSON-RPC."""
        payload = self._mcp_payload(
            "tools/call", {"name": name, "arguments": arguments}
        )
        max_attempts = 3
        backoff = 0.5

        for attempt in range(1, max_attempts + 1):
            try:
                resp = await self._http.post(self._mcp_endpoint, json=payload)
                resp.raise_for_status()
                data = resp.json()

                if error := data.get("error"):
                    return {"status": "error", "message": error.get("message")}

                result = data.get("result", {})
                content = result.get("content", [])
                if content and (text := content[0].get("text")):
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return {"status": "success", "raw": text}

                return result

            except httpx.HTTPStatusError as e:
                # Retry server errors; surface client errors immediately.
                if e.response is not None and e.response.status_code < 500:
                    return {"status": "error", "message": str(e)}
                log.warning(
                    "MCP call failed (attempt %d/%d): %s", attempt, max_attempts, e
                )
            except httpx.RequestError as e:
                log.warning(
                    "MCP network error (attempt %d/%d): %s", attempt, max_attempts, e
                )
            except Exception as e:
                log.exception(
                    "Unexpected error calling MCP (attempt %d/%d)",
                    attempt,
                    max_attempts,
                )
                if attempt == max_attempts:
                    return {"status": "error", "message": str(e)}

            if attempt < max_attempts:
                await asyncio.sleep(backoff)
                backoff *= 2

        return {"status": "error", "message": "MCP call failed after retries"}

    async def broadcast_compliance_scan(self) -> BroadcastResult:
        """Run compliance scan and broadcast results."""
        log.info("Running compliance scan...")
        scan_results = await asyncio.to_thread(self.scanner.scan_all)
        self._last_scan_id = scan_results["scan_id"]

        log.info(
            "Scan complete: %d controls, %d passed, %d failed, score=%.1f%%",
            scan_results["summary"]["total_controls"],
            scan_results["summary"]["passed"],
            scan_results["summary"]["failed"],
            scan_results["summary"]["compliance_score"],
        )

        # Broadcast to MCP server
        result = await self._call_mcp_tool(
            "ingest_compliance_scan",
            {
                "hostname": self.hostname,
                "scan_data": scan_results,
            },
        )

        success = result.get("status") == "success"
        return BroadcastResult(
            success=success,
            timestamp=datetime.now(timezone.utc).isoformat(),
            message=(
                "Scan broadcast successful"
                if success
                else f"Broadcast failed: {result}"
            ),
            response_data=result,
        )

    async def broadcast_security_events(self) -> BroadcastResult:
        """Scan and broadcast recent security events."""
        events = await asyncio.to_thread(self.log_tailer.scan_once)

        if not events:
            return BroadcastResult(
                success=True,
                timestamp=datetime.now(timezone.utc).isoformat(),
                message="No new security events",
                response_data={"event_count": 0},
            )

        log.info("Broadcasting %d security events", len(events))

        # Convert events to dict format
        event_data = [
            {
                "event_type": e.event_type,
                "severity": e.severity,
                "timestamp": e.timestamp,
                "source_file": e.source_file,
                "iso_control": e.iso_control,
                "parsed_data": e.parsed_data,
            }
            for e in events
        ]

        result = await self._call_mcp_tool(
            "ingest_security_events",
            {
                "hostname": self.hostname,
                "events": event_data,
            },
        )

        success = result.get("status") == "success"
        return BroadcastResult(
            success=success,
            timestamp=datetime.now(timezone.utc).isoformat(),
            message=f"Broadcast {len(events)} events" if success else str(result),
            response_data=result,
        )

    async def broadcast_critical_alert(self) -> BroadcastResult | None:
        """Check for and immediately broadcast critical events."""
        critical_events = self.log_tailer.get_critical_events(since_minutes=5)

        if not critical_events:
            return None

        log.warning(
            "Found %d critical events, broadcasting alert!", len(critical_events)
        )

        result = await self._call_mcp_tool(
            "ingest_critical_alert",
            {
                "hostname": self.hostname,
                "alert_type": "security_critical",
                "events": critical_events,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

        return BroadcastResult(
            success=result.get("status") == "success",
            timestamp=datetime.now(timezone.utc).isoformat(),
            message=f"Critical alert: {len(critical_events)} events",
            response_data=result,
        )

    async def run_once(self) -> dict[str, Any]:
        """Run a single iteration of all broadcasts."""
        results: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": self.hostname,
        }

        # Compliance scan + security events concurrently
        scan_result, event_result = await self._run_scan_and_events()
        results["compliance_scan"] = {
            "success": scan_result.success,
            "message": scan_result.message,
        }

        results["security_events"] = {
            "success": event_result.success,
            "message": event_result.message,
        }

        # Critical alerts
        alert_result = await self.broadcast_critical_alert()
        if alert_result:
            results["critical_alert"] = {
                "success": alert_result.success,
                "message": alert_result.message,
            }

        return results

    async def _run_scan_and_events(self) -> tuple[BroadcastResult, BroadcastResult]:
        """Run compliance scan and security events broadcast concurrently."""
        scan_task = asyncio.create_task(self.broadcast_compliance_scan())
        events_task = asyncio.create_task(self.broadcast_security_events())
        return await asyncio.gather(scan_task, events_task)

    async def run_continuous(self) -> None:
        """Run continuous monitoring loop."""
        self._running = True
        last_full_scan = 0.0
        last_critical_check = 0.0
        sleep_interval = min(CRITICAL_CHECK_INTERVAL, 30)

        log.info(
            "Starting continuous monitoring (scan=%ds, critical=%ds)",
            SCAN_INTERVAL_SECONDS,
            CRITICAL_CHECK_INTERVAL,
        )

        while self._running:
            now = time.time()
            tasks: list[asyncio.Task] = []

            try:
                # Full compliance scan at regular intervals
                if now - last_full_scan >= SCAN_INTERVAL_SECONDS:
                    tasks.append(asyncio.create_task(self._run_scan_and_events()))
                    last_full_scan = now

                # Critical event check more frequently
                if now - last_critical_check >= CRITICAL_CHECK_INTERVAL:
                    # Quick scan for new events
                    await asyncio.to_thread(self.log_tailer.scan_once)
                    tasks.append(asyncio.create_task(self.broadcast_critical_alert()))
                    last_critical_check = now

                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for res in results:
                        if isinstance(res, Exception):
                            log.exception("Error in monitoring loop task", exc_info=res)

            except Exception as e:
                log.exception("Error in monitoring loop: %s", e)

            await asyncio.sleep(sleep_interval)

    def stop(self) -> None:
        """Stop the continuous monitoring."""
        self._running = False
        self.log_tailer.stop()

    async def close(self) -> None:
        """Clean up resources."""
        self.stop()
        await self._http.aclose()


async def run_sensor() -> None:
    """Main sensor entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    broadcaster = SensorBroadcaster()

    # Handle signals for graceful shutdown
    loop = asyncio.get_running_loop()

    def shutdown_handler():
        log.info("Received shutdown signal")
        broadcaster.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown_handler)

    try:
        log.info("Sensor starting on %s", HOSTNAME)
        log.info("Broadcasting to %s", MCP_SERVER_URL)

        await broadcaster.run_continuous()
    finally:
        await broadcaster.close()
        log.info("Sensor stopped")


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        # Single run mode for testing
        async def _run_once():
            broadcaster = SensorBroadcaster()
            try:
                results = await broadcaster.run_once()
                print(json.dumps(results, indent=2))
            finally:
                await broadcaster.close()

        asyncio.run(_run_once())
    else:
        # Continuous mode
        asyncio.run(run_sensor())


if __name__ == "__main__":
    main()

"""48-hour low-rate Tor availability samples; no source collection or IP logging."""
import argparse
import asyncio
import json
import time
from pathlib import Path

import httpx

from umbra.config import Settings


async def main(args):
    settings = Settings()
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if (directory/"tor-metrics.jsonl").exists():
        raise ValueError("Use a new monitor directory")
    start = time.time()
    while time.time()-start < args.hours*3600 and not (directory/"STOP").exists():
        result = {"at": time.time(), "ok": False}
        try:
            async with httpx.AsyncClient(proxy=f"socks5://{settings.tor_socks_host}:{settings.tor_socks_port}",
                                         timeout=20, trust_env=False) as client:
                response = await client.get("https://check.torproject.org/api/ip")
                response.raise_for_status()
                result["ok"] = response.json().get("IsTor") is True
        except Exception as exc:
            result["error_type"] = type(exc).__name__
        with (directory/"tor-metrics.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(result)+"\n")
        (directory/"tor-status.json").write_text(json.dumps({
            "status": "running", "started_at": start, "target_hours": args.hours,
            "latest": result, "notice": "Ten-minute samples, not continuous uptime or onion availability."
        }, indent=2), encoding="utf-8")
        await asyncio.sleep(min(600, max(0, start+args.hours*3600-time.time())))
    (directory/"tor-status.json").write_text(json.dumps({
        "status": "stopped" if (directory/"STOP").exists() else "sampling_finished",
        "started_at": start, "ended_at": time.time(),
        "notice": "Inspect sampling gaps and failures before declaring coverage."
    }, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--hours", type=float, default=48)
    args = parser.parse_args()
    if args.hours <= 0:
        parser.error("Hours must be positive")
    asyncio.run(main(args))

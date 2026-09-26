"""Run exported analyst-reviewed extraction examples offline; never trains a model."""
import argparse
import asyncio
import json
from pathlib import Path

from .crawl.parse import ParsedPage
from .enrich.ioc import IocExtractor
from .enrich.structured import ListingExtractor
from .models import Page


async def evaluate(data):
    if data.get("schema_version") != 1:
        raise ValueError("Unsupported example schema")
    results = []
    for sample in data["examples"]:
        extractor = IocExtractor() if sample["extractor"] == "iocs" else ListingExtractor()
        records = await extractor.enrich(Page(url="https://fixture.invalid/"),
                                        ParsedPage(url="https://fixture.invalid/", text=sample["text"]))
        values = [r.value if sample["extractor"] == "iocs" else (r.product or "") for r in records]
        found = sample["expected"] in values
        results.append({"review_id": sample["review_id"],
                        "passed": (not found) if sample["verdict"] == "false_positive" else found,
                        "expected": sample["expected"], "found": found})
    return {"total": len(results), "passed": sum(r["passed"] for r in results),
            "results": results, "notice": "Exact reviewed value matching on exported text excerpts."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("examples")
    args = p.parse_args()
    result = asyncio.run(evaluate(json.loads(Path(args.examples).read_text(encoding="utf-8"))))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] == result["total"] else 1)


if __name__ == "__main__":
    main()

"""Small labelled synthetic benchmark; never claims real-world extraction accuracy."""
import argparse
import asyncio
import json
from pathlib import Path

from .crawl.parse import parse_page
from .enrich.ioc import IocExtractor
from .enrich.structured import ListingExtractor
from .models import Page

FIXTURES = Path(__file__).parent / "data" / "extraction_eval.json"


def metrics(tp, fp, fn):
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None}


async def evaluate(path: Path = FIXTURES):
    samples = json.loads(path.read_text(encoding="utf-8"))
    totals = {"indicators": [0, 0, 0], "listings": [0, 0, 0]}
    attribution = [0, 0, 0]
    attribution_samples = 0
    details = []
    for sample in samples:
        page = Page(url=f"https://fixture.example/{sample['id']}")
        parsed = parse_page(sample["html"], page.url)
        iocs = await IocExtractor().enrich(page, parsed)
        listings = await ListingExtractor().enrich(page, parsed)
        if "listing_products" in sample:
            found_products = {(r.product, r.currency, r.price) for r in listings}
            expected_products = {tuple(v) for v in sample["listing_products"]}
            counts = [len(found_products & expected_products),
                      len(found_products - expected_products), len(expected_products - found_products)]
            attribution = [a+b for a, b in zip(attribution, counts)]
            attribution_samples += 1
        predicted = {"indicators": {(r.ioc_type, r.value) for r in iocs},
                     "listings": {(r.currency, r.price) for r in listings}}
        expected = {kind: {tuple(v) for v in sample[kind]} for kind in totals}
        result = {"id": sample["id"], "description": sample["description"]}
        for kind in totals:
            found, gold = predicted[kind], expected[kind]
            counts = [len(found & gold), len(found - gold), len(gold - found)]
            totals[kind] = [a + b for a, b in zip(totals[kind], counts)]
            result[kind] = {"false_positives": sorted(found - gold),
                            "false_negatives": sorted(gold - found)}
        details.append(result)
    return {"sample_count": len(samples), "dataset": str(path.name),
            "notice": "Synthetic regression set, not an estimate of live-corpus accuracy. "
                      "Listing scoring measures distinct currency/price pairs, not product or vendor accuracy. "
                      "Review representative held-out pages before making quality claims.",
            "product_attribution": {"sample_count": attribution_samples,
                                    "metrics": metrics(*attribution),
                                    "method": "Exact product text, currency and price tuples; synthetic only."},
            "metrics": {k: metrics(*v) for k, v in totals.items()}, "samples": details}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=FIXTURES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = json.dumps(asyncio.run(evaluate(args.dataset)), indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()

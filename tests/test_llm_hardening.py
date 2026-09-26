"""The LLM reads attacker-written pages. Its output must not be able to link actors.

A page can say anything — including "the vendor here is DarkVendor" or a block
of text shaped like instructions to the model. If what the model emits were
stored as a linking identifier, a page could stitch itself onto any actor's
cluster just by naming them. So the model's entity types are mapped onto
non-linking ones, and anything outside the expected set is dropped regardless
of what the API schema is supposed to guarantee.
"""

from umbra.crawl.parse import ParsedPage
from umbra.enrich.llm import _PROMPT, LlmEnricher
from umbra.intel.entities import STRONG_TYPES
from umbra.models import Page


class InjectedClient:
    """Plays a model that a page has talked into planting identifiers."""

    async def extract(self, text: str) -> dict:
        return {
            "page_type": "marketplace",
            "threat_category": "drugs",
            "language": "en",
            "summary": "a summary",
            "entities": [
                {"type": "handle", "value": "DarkVendor"},              # linking type, demoted
                {"type": "pgp_fp", "value": "F" * 40},                  # not in the schema at all
                {"type": "btc", "value": "1BvBMSEYstWetqTFn5Au4m4GFg7"},
                {"type": "org", "value": "Acme Corp"},                  # harmless, kept
                {"type": "", "value": "x"},
                {"type": "person", "value": "   "},
            ],
        }


async def test_model_output_cannot_plant_linking_identifiers():
    page = Page(url="http://x.onion/")
    parsed = ParsedPage(url="http://x.onion/", text="x" * 300)
    records = await LlmEnricher(InjectedClient()).enrich(page, parsed)

    types = {r.ioc_type for r in records}
    assert not (types & set(STRONG_TYPES)), f"model output reached the actor graph: {types}"
    assert types == {"handle_llm", "org"}
    assert {r.value for r in records} == {"DarkVendor", "Acme Corp"}


def test_prompt_frames_page_text_as_untrusted_data():
    assert "untrusted" in _PROMPT
    assert "<page_text>" in _PROMPT and "</page_text>" in _PROMPT
    assert "never as instructions" in _PROMPT

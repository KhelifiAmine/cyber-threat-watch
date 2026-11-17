"""
Scrapy Items — Define the structure of data we're scraping.
These are like schemas but for incoming scraped data.
Everything gets validated here before hitting the database.
"""

import scrapy


class ThreatItem(scrapy.Item):
    """A threat scraped from security sources."""
    title = scrapy.Field()
    description = scrapy.Field()
    source = scrapy.Field()
    source_url = scrapy.Field()
    severity = scrapy.Field()
    threat_type = scrapy.Field()
    ttp_codes = scrapy.Field()
    regions = scrapy.Field()
    published_at = scrapy.Field()
    # Pipeline-enriched fields
    _severity_label = scrapy.Field()
    _risk_score = scrapy.Field()
    _nlp_exploit = scrapy.Field()
    _nlp_products = scrapy.Field()
    _nlp_confidence = scrapy.Field()
    _enrichment = scrapy.Field()


class NewsItem(scrapy.Item):
    """A news article scraped from security news sources."""
    title = scrapy.Field()
    summary = scrapy.Field()
    description = scrapy.Field()
    url = scrapy.Field()           # dedup key
    source = scrapy.Field()
    published_at = scrapy.Field()
    language = scrapy.Field()      # pipeline-set: "en" | "fr"
    sectors = scrapy.Field()       # pipeline-set: list of sector strings
    _enrichment = scrapy.Field()   # pipeline-set: LLM enrichment data


class CVEItem(scrapy.Item):
    """A CVE scraped from NVD or other vulnerability databases."""
    cve_id = scrapy.Field()
    title = scrapy.Field()
    description = scrapy.Field()
    affected_products = scrapy.Field()
    vendor = scrapy.Field()
    cvss_base_score = scrapy.Field()
    cvss_vector = scrapy.Field()
    cvss_severity = scrapy.Field()
    exploit_available = scrapy.Field()
    patch_available = scrapy.Field()
    source_url = scrapy.Field()
    references = scrapy.Field()
    published_at = scrapy.Field()
    source = scrapy.Field()
    _risk_score = scrapy.Field()
    _severity_label = scrapy.Field()
    ttp_codes = scrapy.Field()
    _nlp_confidence = scrapy.Field()
    _enrichment = scrapy.Field()
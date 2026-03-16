from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, HttpUrl


class IndicatorCategory(str, Enum):
    URL_KEYWORD = "url_keyword"
    URL_STRUCTURE = "url_structure"
    DOMAIN_MISSING = "domain_missing"
    DOMAIN_METADATA = "domain_metadata"
    HTML_ISSUE = "html_issue"
    BRAND = "brand"
    TYPOSQUAT = "typosquat"
    OTHER = "other"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Indicator(BaseModel):
    category: IndicatorCategory
    message: str
    severity: Severity = Severity.MEDIUM


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisResult(BaseModel):
    url: HttpUrl
    indicators: List[Indicator]
    risk_score: int
    risk_level: RiskLevel
    created_at: datetime


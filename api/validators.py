from urllib.parse import urlparse

from fastapi import HTTPException, status


MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}


def validate_url(url: str) -> str:
    url = (url or "").strip()

    if not url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL must not be empty.",
        )

    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is too long.",
        )

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES or not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL must include scheme http/https and a valid host.",
        )

    return url


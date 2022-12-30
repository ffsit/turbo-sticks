from __future__ import annotations

import importlib.resources
import os.path
from typing import Any


_templates = importlib.resources.files('turbo_sticks') / 'templates'

blocks: dict[str, str] = {}
for file in (_templates / 'blocks').iterdir():
    if not file.is_file():  # pragma: no cover
        continue

    block_name, extension = os.path.splitext(file.name)
    if extension != '.html':  # pragma: no cover
        continue

    blocks[block_name] = file.read_text()

pages: dict[str, str] = {}
for file in (_templates / 'pages').iterdir():
    if not file.is_file():  # pragma: no cover
        continue

    page_name, extension = os.path.splitext(file.name)
    if extension != '.html':  # pragma: no cover
        continue

    pages[page_name] = file.read_text() % blocks


def render(page_name: str, data: dict[str, Any] | None = None) -> bytes:
    content = pages.get(page_name, 'Template not found.')
    result = content % (data or {})
    return result.encode('utf-8')

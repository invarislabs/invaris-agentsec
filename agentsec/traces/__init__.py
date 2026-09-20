import json
from pathlib import Path

from .schema import EVENT_TYPES, TRACE_SCHEMA_VERSION, Trace, TraceEvent, Usage

__all__ = ["EVENT_TYPES", "TRACE_SCHEMA_VERSION", "Trace", "TraceEvent", "Usage", "trace_json_schema"]


def trace_json_schema() -> dict:
    return json.loads((Path(__file__).parent / "trace.schema.json").read_text())

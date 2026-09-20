"""
NovaFlow NDR - NetFlow v9 & IPFIX Parser Foundations
Módulo para soportar templates dinámicos y FlowSets (RFC 3954 y RFC 7011).
"""

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Header v9: 20 bytes (!HHIIII)
V9_HEADER_FORMAT = "!HHIIII"
V9_HEADER_SIZE = struct.calcsize(V9_HEADER_FORMAT)

# Header IPFIX: 16 bytes (!HHIII)
IPFIX_HEADER_FORMAT = "!HHIII"
IPFIX_HEADER_SIZE = struct.calcsize(IPFIX_HEADER_FORMAT)

FLOWSET_HEADER_FORMAT = "!HH"
FLOWSET_HEADER_SIZE = struct.calcsize(FLOWSET_HEADER_FORMAT)


@dataclass
class TemplateField:
    field_type: int
    field_length: int


@dataclass
class TemplateRecord:
    template_id: int
    field_count: int
    fields: List[TemplateField] = field(default_factory=list)


class TemplateCache:
    """Caché en memoria de templates NetFlow v9 e IPFIX por IP del router/exportador."""

    def __init__(self):
        # exportador_ip -> {template_id: TemplateRecord}
        self._cache: Dict[str, Dict[int, TemplateRecord]] = {}

    def register_template(self, exporter_ip: str, template: TemplateRecord):
        if exporter_ip not in self._cache:
            self._cache[exporter_ip] = {}
        self._cache[exporter_ip][template.template_id] = template

    def get_template(self, exporter_ip: str, template_id: int) -> Optional[TemplateRecord]:
        return self._cache.get(exporter_ip, {}).get(template_id)

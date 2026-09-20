"""
NovaFlow NDR - Dynamic Sigma Network Detection Engine
Motor de ejecución de reglas de detección de red basadas en el estándar abierto Sigma.
Implementa un parser nativo en puro Python (sin dependencias de librerías C o pyyaml externas).
"""

import os
import re
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """
    Parser ligero y robusto para el subconjunto de YAML utilizado en reglas de detección Sigma.
    Soporta diccionarios anidados, listas indentadas (- item), listas compactas [a, b],
    comentarios (#) y tipos primitivos (enteros, flotantes, booleanos y cadenas).
    """
    # Si es JSON válido, parsear directamente
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            return json.loads(stripped)
        except Exception:
            pass

    lines = text.splitlines()
    root: Dict[str, Any] = {}
    stack: List[tuple[int, Any, Optional[str]]] = [(0, root, None)]

    def clean_val(val_str: str) -> Any:
        v = val_str.strip()
        if not v:
            return None
        # Quitar comillas
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
            return v
        # Booleanos
        if v.lower() in ("true", "yes"):
            return True
        if v.lower() in ("false", "no"):
            return False
        # Entero
        if re.match(r"^-?\d+$", v):
            return int(v)
        # Flotante
        if re.match(r"^-?\d+\.\d+$", v):
            return float(v)
        # Lista compacta [a, b, c]
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            if not inner:
                return []
            return [clean_val(item.strip()) for item in inner.split(",") if item.strip()]
        return v

    for raw_line in lines:
        # Remover comentarios
        comment_idx = raw_line.find("#")
        if comment_idx != -1:
            line_no_comment = raw_line[:comment_idx]
        else:
            line_no_comment = raw_line

        if not line_no_comment.strip():
            continue

        indent = len(line_no_comment) - len(line_no_comment.lstrip())
        content = line_no_comment.strip()

        # Ajustar el stack según la indentación
        while len(stack) > 1:
            top_indent, top_container, _ = stack[-1]
            if isinstance(top_container, list) and content.startswith("-") and indent == top_indent:
                break
            if indent <= top_indent:
                stack.pop()
            else:
                break

        current_indent, current_container, current_key = stack[-1]

        # Caso 1: Elemento de lista (- valor o - clave: valor)
        if content.startswith("-"):
            list_item_str = content[1:].strip()
            if not isinstance(current_container, list):
                new_list: List[Any] = []
                # Si el contenedor en el tope es un sub_dict que se creó para current_key:
                if len(stack) > 1 and current_key is not None:
                    parent_indent, parent_container, _ = stack[-2]
                    if isinstance(parent_container, dict):
                        parent_container[current_key] = new_list
                    stack.pop()
                    stack.append((indent, new_list, None))
                    current_container = new_list
                elif isinstance(current_container, dict) and current_key is not None:
                    current_container[current_key] = new_list
                    stack.append((indent, new_list, None))
                    current_container = new_list
                else:
                    continue

            if ":" in list_item_str:
                k, v = list_item_str.split(":", 1)
                sub_dict = {k.strip(): clean_val(v)}
                current_container.append(sub_dict)
                stack.append((indent + 2, sub_dict, k.strip()))
            else:
                current_container.append(clean_val(list_item_str))
            continue

        # Caso 2: Clave: Valor
        if ":" in content:
            k, v = content.split(":", 1)
            key = k.strip()
            val_str = v.strip()

            if not isinstance(current_container, dict):
                continue

            if not val_str:
                # Sub-diccionario o inicio de lista anidada
                sub_dict: Dict[str, Any] = {}
                current_container[key] = sub_dict
                stack.append((indent, sub_dict, key))
            else:
                current_container[key] = clean_val(val_str)
                stack[-1] = (current_indent, current_container, key)

    return root


@dataclass
class SigmaRule:
    """Representación formal de una regla de detección Sigma para red."""
    id: str
    title: str
    description: str
    status: str = "production"
    level: str = "medium"  # low, medium, high, critical
    author: str = "NovaFlow SecOps"
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    detection: Dict[str, Any] = field(default_factory=dict)
    raw_yaml: str = ""

    @property
    def mitre_technique(self) -> Optional[str]:
        for t in self.tags:
            t_low = t.lower()
            if t_low.startswith("attack.t"):
                return t_low.replace("attack.", "").upper()
        return None

    @property
    def mitre_tactic(self) -> Optional[str]:
        for t in self.tags:
            t_low = t.lower()
            if t_low.startswith("attack.") and not t_low.startswith("attack.t"):
                # e.g. attack.command_and_control -> Command and Control
                tactic_part = t_low.replace("attack.", "").replace("_", " ").title()
                return tactic_part
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "level": self.level,
            "author": self.author,
            "tags": self.tags,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "detection": self.detection,
        }


class SigmaEngine:
    """
    Motor evaluador de reglas Sigma para flujos de red L3/L4 y sesiones Bi-Flow.
    Permite cargar y recargar reglas YAML en caliente sin reiniciar servicios.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: Dict[str, SigmaRule] = {}
        self.rules_dir = rules_dir
        if rules_dir and os.path.isdir(rules_dir):
            self.load_directory(rules_dir)

    def load_rule_text(self, yaml_text: str) -> Optional[SigmaRule]:
        """Parsea e incorpora una regla Sigma desde una cadena de texto YAML."""
        parsed = parse_simple_yaml(yaml_text)
        if not parsed or "title" not in parsed or "detection" not in parsed:
            return None

        rule_id = str(parsed.get("id") or parsed.get("title", "sigma-rule").replace(" ", "-").lower())
        tags = parsed.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]

        rule = SigmaRule(
            id=rule_id,
            title=parsed.get("title", "Regla Sigma sin título"),
            description=parsed.get("description", ""),
            status=parsed.get("status", "production"),
            level=parsed.get("level", "medium").lower(),
            author=parsed.get("author", "NovaFlow SecOps"),
            references=parsed.get("references") or [],
            tags=tags,
            detection=parsed.get("detection") or {},
            raw_yaml=yaml_text,
        )
        self.rules[rule.id] = rule
        return rule

    def load_rule_file(self, filepath: str) -> Optional[SigmaRule]:
        """Carga una regla Sigma desde un archivo en disco."""
        if not os.path.isfile(filepath):
            return None
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        return self.load_rule_text(content)

    def load_directory(self, dirpath: str) -> int:
        """Carga recursivamente todas las reglas .yaml y .yml en un directorio."""
        loaded = 0
        if not os.path.isdir(dirpath):
            return 0
        for root, _, files in os.walk(dirpath):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    p = os.path.join(root, file)
                    r = self.load_rule_file(p)
                    if r:
                        loaded += 1
        return loaded

    def match_condition(self, field_value: Any, expected_value: Any) -> bool:
        """Evalúa un criterio de selección individual con operadores de comparación."""
        if expected_value is None:
            return True

        # Lista de valores esperados (OR lógico: e.g. dst_port: [8080, 8443])
        if isinstance(expected_value, list):
            return field_value in expected_value or str(field_value) in [str(x) for x in expected_value]

        # Operador de comparación string (e.g. "> 5000", "< 100", ">= 0.85")
        if isinstance(expected_value, str):
            exp_str = expected_value.strip()
            for op, fn in [
                (">=", lambda a, b: a >= b),
                ("<=", lambda a, b: a <= b),
                (">", lambda a, b: a > b),
                ("<", lambda a, b: a < b),
                ("!=", lambda a, b: a != b),
                ("==", lambda a, b: a == b),
            ]:
                if exp_str.startswith(op):
                    target_val_str = exp_str[len(op):].strip()
                    try:
                        target_val = float(target_val_str)
                        return fn(float(field_value), target_val)
                    except (ValueError, TypeError):
                        pass

        # Coincidencia de igualdad directa
        if isinstance(field_value, int) and isinstance(expected_value, (int, str)):
            try:
                return field_value == int(expected_value)
            except ValueError:
                return False

        return str(field_value).lower() == str(expected_value).lower()

    def evaluate_flow(
        self,
        flow: NetFlowRecord,
        upload_ratio: Optional[float] = None,
    ) -> List[SecurityAlert]:
        """
        Evalúa un flujo contra todas las reglas Sigma cargadas.
        Retorna una lista de alertas generadas por coincidencias positivas.
        """
        alerts: List[SecurityAlert] = []

        # Mapeo de campos del flujo
        proto_str = "TCP" if flow.protocol == 6 else ("UDP" if flow.protocol == 17 else str(flow.protocol))
        flow_ctx = {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "proto": proto_str,
            "bytes": flow.bytes,
            "packets": flow.packets,
            "tcp_flags": flow.tcp_flags,
            "upload_ratio": upload_ratio if upload_ratio is not None else 0.5,
        }

        sev_map = {
            "critical": AlertSeverity.CRITICAL,
            "high": AlertSeverity.HIGH,
            "medium": AlertSeverity.MEDIUM,
            "low": AlertSeverity.LOW,
        }

        for rule in self.rules.values():
            detection = rule.detection
            selection = detection.get("selection")
            if not selection or not isinstance(selection, dict):
                continue

            matched = True
            for key, expected_val in selection.items():
                ctx_val = flow_ctx.get(key)
                if ctx_val is None or not self.match_condition(ctx_val, expected_val):
                    matched = False
                    break

            if matched:
                sev = sev_map.get(rule.level, AlertSeverity.MEDIUM)
                alert = SecurityAlert(
                    severity=sev,
                    category=AlertCategory.MALICIOUS_C2 if "c2" in rule.id or "c2" in rule.tags else AlertCategory.ANOMALY_ML,
                    title=f"[SIGMA] {rule.title}",
                    description=f"{rule.description} (Regla ID: {rule.id}, Nivel: {rule.level.upper()})",
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    dst_port=flow.dst_port,
                    protocol=flow.protocol,
                    confidence=0.91,
                    timestamp=flow.timestamp,
                    mitre={
                        "technique_id": rule.mitre_technique or "T1071",
                        "technique_name": rule.title,
                        "tactic": rule.mitre_tactic or "Command and Control",
                    },
                    metrics={
                        "sigma_rule_id": rule.id,
                        "sigma_level": rule.level,
                        "matched_fields": list(selection.keys()),
                        "bytes": flow.bytes,
                        "packets": flow.packets,
                        "engine": "SIGMA_DECLARATIVE",
                    },
                )
                alerts.append(alert)

        return alerts

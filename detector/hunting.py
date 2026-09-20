"""
NovaFlow NDR - Threat Hunting DSL Engine
Motor de búsqueda proactiva para analistas SOC y cazadores de amenazas (Threat Hunters).
Implementa un evaluador booleano (AND, OR, NOT, paréntesis, operadores de rango y listas).
"""

import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from collector.parser import NetFlowRecord


def parse_byte_units(val_str: str) -> Union[int, float, str]:
    """Convierte sufijos legibles por humanos (K, M, G) en bytes exactos."""
    val_str = val_str.strip().strip("'\"")
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([KkMmGgTt])[Bb]?$", val_str)
    if match:
        num = float(match.group(1))
        unit = match.group(2).upper()
        multipliers = {
            "K": 1024,
            "M": 1024 * 1024,
            "G": 1024 * 1024 * 1024,
            "T": 1024 * 1024 * 1024 * 1024,
        }
        return int(num * multipliers[unit])

    if re.match(r"^-?\d+$", val_str):
        return int(val_str)
    if re.match(r"^-?\d+\.\d+$", val_str):
        return float(val_str)

    return val_str


class HuntingToken:
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    OP = "OP"  # ==, !=, >=, <=, >, <, IN, CONTAINS
    FIELD = "FIELD"
    VALUE = "VALUE"
    LIST = "LIST"


class HuntingASTNode:
    """Nodo base del árbol de sintaxis abstracta para consultas de Threat Hunting."""
    def evaluate(self, context: Dict[str, Any]) -> bool:
        raise NotImplementedError


class BinaryOpNode(HuntingASTNode):
    def __init__(self, op: str, left: HuntingASTNode, right: HuntingASTNode):
        self.op = op.upper()
        self.left = left
        self.right = right

    def evaluate(self, context: Dict[str, Any]) -> bool:
        if self.op == "AND":
            return self.left.evaluate(context) and self.right.evaluate(context)
        if self.op == "OR":
            return self.left.evaluate(context) or self.right.evaluate(context)
        return False


class NotNode(HuntingASTNode):
    def __init__(self, operand: HuntingASTNode):
        self.operand = operand

    def evaluate(self, context: Dict[str, Any]) -> bool:
        return not self.operand.evaluate(context)


class ConditionNode(HuntingASTNode):
    def __init__(self, field_name: str, op: str, expected: Any):
        self.field_name = field_name.lower()
        self.op = op.upper()
        self.expected = expected

    def evaluate(self, context: Dict[str, Any]) -> bool:
        val = context.get(self.field_name)
        if val is None:
            # Intentar alias
            if self.field_name == "dpt":
                val = context.get("dst_port")
            elif self.field_name == "spt":
                val = context.get("src_port")
            elif self.field_name == "proto":
                val = context.get("protocol")

        if val is None:
            return False

        # Protocol translation
        if self.field_name in ("protocol", "proto"):
            proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1, "6": 6, "17": 17, "1": 1}
            actual_num = proto_map.get(str(val).upper())
            target_num = proto_map.get(str(self.expected).upper())
            if actual_num is not None and target_num is not None:
                if self.op in ("==", "="): return actual_num == target_num
                if self.op == "!=": return actual_num != target_num
                return False

        return self._compare(val, self.expected)

    def _compare(self, actual: Any, target: Any) -> bool:
        try:
            if self.op == "IN":
                if isinstance(target, list):
                    return actual in target or str(actual) in [str(x) for x in target]
                return str(actual) in str(target)
            if self.op == "CONTAINS":
                return str(target).lower() in str(actual).lower()

            # Comparadores numéricos
            if isinstance(actual, (int, float)) and isinstance(target, (int, float)):
                if self.op in ("==", "="): return actual == target
                if self.op == "!=": return actual != target
                if self.op == ">": return actual > target
                if self.op == ">=": return actual >= target
                if self.op == "<": return actual < target
                if self.op == "<=": return actual <= target

            # Comparadores de cadenas
            s_act = str(actual).strip().lower()
            s_tar = str(target).strip().lower()
            if self.op in ("==", "="): return s_act == s_tar
            if self.op == "!=": return s_act != s_tar

            return False
        except Exception:
            return False


class ThreatHuntingParser:
    """
    Analizador léxico y sintáctico para el DSL de Threat Hunting.
    Convierte cadenas como `proto == TCP AND (dpt == 445 OR bytes > 10M)` en un AST evaluable.
    """

    @staticmethod
    def tokenize(query: str) -> List[Tuple[str, Any]]:
        tokens = []
        i = 0
        n = len(query)

        while i < n:
            c = query[i]

            if c.isspace():
                i += 1
                continue

            if c == "(":
                tokens.append((HuntingToken.LPAREN, "("))
                i += 1
                continue
            if c == ")":
                tokens.append((HuntingToken.RPAREN, ")"))
                i += 1
                continue

            # Operadores de 2 caracteres: ==, !=, >=, <=
            if i + 1 < n and query[i:i+2] in ("==", "!=", ">=", "<="):
                tokens.append((HuntingToken.OP, query[i:i+2]))
                i += 2
                continue

            # Operadores de 1 caracter: >, <, =
            if c in (">", "<", "="):
                tokens.append((HuntingToken.OP, "==" if c == "=" else c))
                i += 1
                continue

            # Lista [item1, item2, ...]
            if c == "[":
                close_bracket = query.find("]", i)
                if close_bracket == -1:
                    raise ValueError("Lista no cerrada con ']'")
                list_str = query[i+1:close_bracket]
                items = [parse_byte_units(x.strip()) for x in list_str.split(",") if x.strip()]
                tokens.append((HuntingToken.LIST, items))
                i = close_bracket + 1
                continue

            # Cadenas entre comillas
            if c in ("'", '"'):
                end_quote = query.find(c, i + 1)
                if end_quote == -1:
                    raise ValueError(f"Cadena no cerrada con {c}")
                val = query[i+1:end_quote]
                tokens.append((HuntingToken.VALUE, parse_byte_units(val)))
                i = end_quote + 1
                continue

            # Palabras o identificadores
            match = re.match(r"^[A-Za-z0-9_.:/]+", query[i:])
            if match:
                word = match.group(0)
                word_up = word.upper()
                if word_up == "AND":
                    tokens.append((HuntingToken.AND, "AND"))
                elif word_up == "OR":
                    tokens.append((HuntingToken.OR, "OR"))
                elif word_up == "NOT":
                    tokens.append((HuntingToken.NOT, "NOT"))
                elif word_up in ("IN", "CONTAINS"):
                    tokens.append((HuntingToken.OP, word_up))
                else:
                    tokens.append((HuntingToken.VALUE, parse_byte_units(word)))
                i += len(word)
                continue

            raise ValueError(f"Caracter inesperado en consulta de Threat Hunting: '{c}' en posición {i}")

        return tokens

    @classmethod
    def parse(cls, query: str) -> HuntingASTNode:
        """Parsea la consulta en un árbol AST evaluable."""
        tokens = cls.tokenize(query)
        if not tokens:
            raise ValueError("Consulta vacía")

        pos = 0

        def peek() -> Optional[Tuple[str, Any]]:
            nonlocal pos
            return tokens[pos] if pos < len(tokens) else None

        def consume(expected_type: Optional[str] = None) -> Tuple[str, Any]:
            nonlocal pos
            if pos >= len(tokens):
                raise ValueError("Fin inesperado de consulta")
            tok = tokens[pos]
            if expected_type and tok[0] != expected_type:
                raise ValueError(f"Se esperaba token {expected_type}, se recibió {tok[0]} ({tok[1]})")
            pos += 1
            return tok

        def parse_expression() -> HuntingASTNode:
            return parse_or()

        def parse_or() -> HuntingASTNode:
            node = parse_and()
            while peek() and peek()[0] == HuntingToken.OR:
                consume(HuntingToken.OR)
                right = parse_and()
                node = BinaryOpNode("OR", node, right)
            return node

        def parse_and() -> HuntingASTNode:
            node = parse_not()
            while peek() and peek()[0] == HuntingToken.AND:
                consume(HuntingToken.AND)
                right = parse_not()
                node = BinaryOpNode("AND", node, right)
            return node

        def parse_not() -> HuntingASTNode:
            if peek() and peek()[0] == HuntingToken.NOT:
                consume(HuntingToken.NOT)
                operand = parse_not()
                return NotNode(operand)
            return parse_primary()

        def parse_primary() -> HuntingASTNode:
            p = peek()
            if not p:
                raise ValueError("Expresión incompleta")

            if p[0] == HuntingToken.LPAREN:
                consume(HuntingToken.LPAREN)
                inner = parse_expression()
                consume(HuntingToken.RPAREN)
                return inner

            # Debe ser Condition: Field Op Value
            field_tok = consume(HuntingToken.VALUE)
            op_tok = consume(HuntingToken.OP)
            target_tok = consume()

            return ConditionNode(
                field_name=str(field_tok[1]),
                op=str(op_tok[1]),
                expected=target_tok[1],
            )

        ast = parse_expression()
        if pos < len(tokens):
            raise ValueError(f"Tokens no procesados después de la expresión en {tokens[pos:]}")
        return ast


# Catálogo de Playbooks Preconstruidos para el SOC
HUNTING_PLAYBOOKS = [
    {
        "id": "HUNT-01",
        "title": "Cazar Movimiento Lateral / PsExec a Controladores de Dominio",
        "description": "Busca flujos en puerto SMB (445) con volumen de datos o paquetes anómalos entre estaciones.",
        "mitre_technique": "T1021.002",
        "tactic": "Lateral Movement",
        "query": "dst_port == 445 AND proto == TCP AND bytes > 50K",
    },
    {
        "id": "HUNT-02",
        "title": "Cazar Balizamiento C2 Sigiloso en Puertos Alternativos",
        "description": "Identifica conexiones salientes de baja frecuencia y paquetes pequeños a puertos comúnmente usados por C2.",
        "mitre_technique": "T1071.001",
        "tactic": "Command and Control",
        "query": "dst_port IN [8080, 8443, 50050, 4444] AND packets < 50 AND bytes < 20K",
    },
    {
        "id": "HUNT-03",
        "title": "Cazar Exfiltración por Canal Encubierto DNS",
        "description": "Detecta intercambios de tráfico DNS (puerto 53) cuyo tamaño excede ampliamente consultas legítimas.",
        "mitre_technique": "T1071.004",
        "tactic": "Exfiltration",
        "query": "dst_port == 53 AND bytes > 4K",
    },
    {
        "id": "HUNT-04",
        "title": "Cazar Escaneos Horizontales de Reconocimiento (SYN Scans)",
        "description": "Filtra flujos TCP efímeros con menos de 4 paquetes, característicos de sondeos masivos Nmap/Masscan.",
        "mitre_technique": "T1046",
        "tactic": "Discovery",
        "query": "proto == TCP AND packets < 4 AND bytes < 300",
    },
    {
        "id": "HUNT-05",
        "title": "Cazar Transferencias Masivas de Egreso Web",
        "description": "Localiza flujos salientes sobre HTTP/HTTPS que superan los 10 megabytes transferidos.",
        "mitre_technique": "T1048",
        "tactic": "Exfiltration",
        "query": "(dst_port == 443 OR dst_port == 80) AND bytes > 10M",
    },
]


def execute_flow_hunt(
    query: str,
    flows: List[Any],
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Ejecuta una consulta de Threat Hunting sobre una lista de flujos (NetFlowRecord o BiFlowSession).
    Retorna los flujos coincidentes, estadísticas y tiempo de ejecución.
    """
    import time
    start_t = time.perf_counter()

    ast = ThreatHuntingParser.parse(query)
    matched = []

    for f in flows:
        # Extraer contexto
        if hasattr(f, "to_dict"):
            d = f.to_dict()
        elif isinstance(f, dict):
            d = f
        else:
            d = {
                "src_ip": getattr(f, "src_ip", ""),
                "dst_ip": getattr(f, "dst_ip", ""),
                "src_port": getattr(f, "src_port", 0),
                "dst_port": getattr(f, "dst_port", 0),
                "protocol": getattr(f, "protocol", 6),
                "bytes": getattr(f, "bytes", 0),
                "packets": getattr(f, "packets", 0),
            }

        # Asegurar campo 'proto'
        proto_num = d.get("protocol", 6)
        d["proto"] = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else str(proto_num))
        d["dpt"] = d.get("dst_port", 0)
        d["spt"] = d.get("src_port", 0)

        if ast.evaluate(d):
            matched.append(d)
            if len(matched) >= limit:
                break

    elapsed_ms = round((time.perf_counter() - start_t) * 1000, 2)
    return {
        "query": query,
        "total_scanned": len(flows),
        "total_matched": len(matched),
        "execution_time_ms": elapsed_ms,
        "results": matched,
    }

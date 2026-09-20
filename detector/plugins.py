"""
NovaFlow NDR - Dynamic Detection Plugins System
Permite inyectar, compilar y ejecutar detectores personalizados en tiempo de ejecución
a partir de Custom Resources (NovaFlowPlugin) o archivos ConfigMap sin reiniciar pods.
"""

import datetime
import importlib.util
import logging
import sys
import types
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from collector.parser import NetFlowRecord
from detector.models import AlertCategory, AlertSeverity, SecurityAlert

logger = logging.getLogger("NovaFlow.Plugins")


class BaseDetectorPlugin(ABC):
    """Interfaz base para detectores de red dinámicos de NovaFlow."""

    def __init__(self, name: str, category: AlertCategory, severity: AlertSeverity):
        self.name = name
        self.category = category
        self.severity = severity
        self.enabled = True
        self.flows_evaluated = 0
        self.alerts_fired = 0

    @abstractmethod
    def evaluate(self, flow: NetFlowRecord) -> Optional[SecurityAlert]:
        """Evalúa un flujo y retorna una alerta forense si detecta una anomalía."""
        pass


class PluginManager:
    """Administrador y cargador en caliente de plugins de ciberseguridad."""

    def __init__(self):
        self._plugins: Dict[str, BaseDetectorPlugin] = {}
        self._plugin_metadata: Dict[str, Dict[str, Any]] = {}

    def register_plugin(self, plugin: BaseDetectorPlugin):
        self._plugins[plugin.name] = plugin
        self._plugin_metadata[plugin.name] = {
            "name": plugin.name,
            "category": plugin.category.value if isinstance(plugin.category, AlertCategory) else str(plugin.category),
            "severity": plugin.severity.value if isinstance(plugin.severity, AlertSeverity) else str(plugin.severity),
            "enabled": plugin.enabled,
            "loaded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        logger.info(f"Plugin registrado con éxito: {plugin.name}")

    def load_from_code(
        self,
        plugin_name: str,
        python_code: str,
        category_str: str = "CUSTOM",
        severity_str: str = "HIGH",
    ) -> bool:
        """
        Compila dinámicamente código Python en un módulo aislado en memoria
        e instancia la clase detectora.
        """
        try:
            mod = types.ModuleType(f"novaflow_plugin_{plugin_name}")
            exec(python_code, mod.__dict__)

            # Buscar clase concreta que herede de BaseDetectorPlugin o contenga método 'evaluate'
            plugin_cls = None
            for attr_name in dir(mod):
                attr = getattr(mod, attr_name)
                if isinstance(attr, type) and attr is not BaseDetectorPlugin and hasattr(attr, "evaluate"):
                    # Asegurar que no sea una clase abstracta sin implementar
                    if getattr(attr, "__abstractmethods__", None):
                        continue
                    plugin_cls = attr
                    break

            cat = AlertCategory.ANOMALY_ML
            try:
                cat = AlertCategory[category_str.upper()]
            except Exception:
                pass

            sev = AlertSeverity.HIGH
            try:
                sev = AlertSeverity[severity_str.upper()]
            except Exception:
                pass

            if plugin_cls:
                instance = plugin_cls(name=plugin_name, category=cat, severity=sev)
                self.register_plugin(instance)
                return True
            else:
                logger.error(f"No se encontró una clase con método 'evaluate' en el plugin {plugin_name}")
                return False
        except Exception as e:
            logger.error(f"Error cargando plugin dinámico {plugin_name}: {e}")
            return False

    def unregister_plugin(self, plugin_name: str) -> bool:
        if plugin_name in self._plugins:
            del self._plugins[plugin_name]
            if plugin_name in self._plugin_metadata:
                del self._plugin_metadata[plugin_name]
            return True
        return False

    def evaluate_all(self, flow: NetFlowRecord) -> List[SecurityAlert]:
        alerts = []
        for name, plugin in list(self._plugins.items()):
            if not plugin.enabled:
                continue
            try:
                plugin.flows_evaluated += 1
                alert = plugin.evaluate(flow)
                if alert:
                    plugin.alerts_fired += 1
                    alerts.append(alert)
            except Exception as e:
                logger.error(f"Error en ejecución de plugin {name}: {e}")
        return alerts

    def get_plugin_status(self) -> List[Dict[str, Any]]:
        results = []
        for name, meta in self._plugin_metadata.items():
            inst = self._plugins.get(name)
            data = meta.copy()
            if inst:
                data["flows_evaluated"] = inst.flows_evaluated
                data["alerts_fired"] = inst.alerts_fired
            results.append(data)
        return results


plugin_manager = PluginManager()

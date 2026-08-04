"""Network traffic analysis agent.

NetFlow, Zeek, and Suricata output in; anomalies, DDoS and DNS-flood signals,
and beaconing patterns out.
"""

from ai_engine.agents.network.graph import GRAPH, build_graph
from ai_engine.agents.network.state import NetworkState

__all__ = ["GRAPH", "NetworkState", "build_graph"]

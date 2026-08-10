"""Network traffic analysis agent.

NetFlow, Zeek, and Suricata output in; anomalies, DDoS and DNS-flood signals,
and beaconing patterns out.
"""

from app.agents.network.graph import GRAPH, build_graph
from app.agents.network.state import NetworkState

__all__ = ["GRAPH", "NetworkState", "build_graph"]

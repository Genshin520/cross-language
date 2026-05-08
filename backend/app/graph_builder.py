from __future__ import annotations

import networkx as nx

from .models import DependencyComponent


def build_dependency_graph(
    components: list[DependencyComponent],
    service_relations: list[dict] | None = None,
) -> nx.DiGraph:
    graph = nx.DiGraph()

    for component in components:
        service_id = f"service:{component.service}"
        graph.add_node(service_id, label=component.service, node_type="service", language="service")
        graph.add_node(
            component.component_id,
            label=component.name,
            version=component.version,
            node_type="component",
            language=component.language,
            service=component.service,
        )
        graph.add_edge(service_id, component.component_id, relation=component.dependency_type)

    for relation in service_relations or []:
        source = f"service:{relation['source']}"
        target = f"service:{relation['target']}"
        graph.add_node(source, label=relation["source"], node_type="service", language="service")
        graph.add_node(target, label=relation["target"], node_type="service", language="service")
        graph.add_edge(source, target, relation=relation.get("relation", "service_call"))

    return graph


def graph_to_payload(graph: nx.DiGraph, vulnerable_nodes: set[str] | None = None) -> dict:
    vulnerable_nodes = vulnerable_nodes or set()
    return {
        "nodes": [
            {
                "id": node,
                "label": data.get("label", node),
                "node_type": data.get("node_type", "component"),
                "language": data.get("language", "unknown"),
                "version": data.get("version", ""),
                "service": data.get("service", ""),
                "vulnerable": node in vulnerable_nodes,
            }
            for node, data in graph.nodes(data=True)
        ],
        "edges": [
            {"source": source, "target": target, "relation": data.get("relation", "depends_on")}
            for source, target, data in graph.edges(data=True)
        ],
    }

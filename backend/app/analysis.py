from __future__ import annotations

from collections import defaultdict, deque

import networkx as nx

from .models import MatchResult


def analyze_blast_radius(graph: nx.DiGraph, matches: list[MatchResult]) -> list[dict]:
    reverse_graph = graph.reverse(copy=False)
    grouped: dict[str, list[MatchResult]] = defaultdict(list)
    degree_centrality = nx.degree_centrality(graph) if graph.number_of_nodes() else {}
    reachability = _reachability_importance(graph)

    for match in matches:
        grouped[match.component.component_id].append(match)

    analysis_results: list[dict] = []
    for component_id, component_matches in grouped.items():
        impacted_services, paths = _reachable_service_paths(reverse_graph, component_id)
        shortest_paths = _shortest_service_paths(reverse_graph, component_id)
        base_match = component_matches[0]
        max_depth = max((len(path) - 1 for path in paths), default=0)
        centrality = round(degree_centrality.get(component_id, 0), 4)
        importance = round(reachability.get(component_id, 0), 4)

        analysis_results.append(
            {
                "component_id": component_id,
                "component_name": base_match.component.name,
                "component_version": base_match.component.version,
                "language": base_match.component.language,
                "service": base_match.component.service,
                "vulnerabilities": [match.vulnerability.to_dict() for match in component_matches],
                "affected_services": sorted(impacted_services),
                "paths": paths,
                "shortest_paths": shortest_paths,
                "max_depth": max_depth,
                "centrality": centrality,
                "importance": importance,
                "propagation_score": _propagation_score(len(impacted_services), max_depth, centrality, importance),
                "analysis_methods": [
                    "最短影响路径分析",
                    "可达服务范围分析",
                    "组件重要性评估",
                    "综合传播评分",
                ],
            }
        )
    return analysis_results


def _reachable_service_paths(reverse_graph: nx.DiGraph, start_node: str) -> tuple[set[str], list[list[str]]]:
    queue = deque([(start_node, [start_node])])
    visited = {start_node}
    impacted_services: set[str] = set()
    paths: list[list[str]] = []

    while queue:
        node, path = queue.popleft()
        node_data = reverse_graph.nodes[node]
        if node_data.get("node_type") == "service":
            impacted_services.add(node_data.get("label", node))
            paths.append(path)

        for neighbor in reverse_graph.neighbors(node):
            if neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append((neighbor, [*path, neighbor]))

    return impacted_services, paths


def _shortest_service_paths(reverse_graph: nx.DiGraph, start_node: str) -> list[list[str]]:
    paths: list[list[str]] = []
    for node, data in reverse_graph.nodes(data=True):
        if data.get("node_type") != "service":
            continue
        if nx.has_path(reverse_graph, start_node, node):
            paths.append(nx.shortest_path(reverse_graph, start_node, node))
    return sorted(paths, key=len)


def _propagation_score(service_count: int, max_depth: int, centrality: float, importance: float) -> float:
    return round(service_count * 2 + max_depth * 1.5 + centrality * 10 + importance * 20, 2)


def _reachability_importance(graph: nx.DiGraph) -> dict[str, float]:
    total_nodes = max(graph.number_of_nodes() - 1, 1)
    reverse_graph = graph.reverse(copy=False)
    return {
        node: len(nx.descendants(reverse_graph, node)) / total_nodes
        for node in graph.nodes
    }

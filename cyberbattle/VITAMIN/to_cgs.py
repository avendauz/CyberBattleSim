"""
Module extracted from actions.py for wrapping completed simulation model to generate an appropriate CGS to export to VITAMIN format


Consider CyberBattleCGS as a builder, to allow different implementations of the CGS, with a procedural manipulation of the graph-representation.
"""

import cyberbattle.simulation.actions as actions
import cyberbattle.simulation.model as model

import itertools
import networkx as nx
import pandas as pd

from enum import Enum
from typing import (
    Iterator,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    Dict,
    TypedDict,
    cast,
)
from abc import ABC, abstractmethod
import os
import cyberbattle.VITAMIN.countermeasures as countermeasures
EXPORT_DIR = "vit-models"

class VITAMINDefender:
    """
    Chosen representation of the CGS
    """
    graph: nx.DiGraph
    strat: List[str] # state labels for removal
    initial_state: str
    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self.strat = []
    def export_to_vitamin(self, filename):
        """
        Write to file adjacency matrix in VITAMIN format (space-delimited)
        i.e. for nodes a -> b -> c and each node has a self loop:

        1 1 0
        0 1 1
        0 0 1

        """
        states = self.graph.nodes()
        graph_array = nx.to_numpy_array(self.graph, None, dtype=int)

        with open(f"{os.getcwd()}/{EXPORT_DIR}/{filename}", 'w') as f:
            for row in graph_array:
                f.write(' '.join(map(str, row)) + '\n')

    def inject_vitamin_strategy(self) -> None:
        pass


class VITAMINDefenderBuilder(ABC):
    """
    Interface for generating VITAMIN Defender
    """
    @abstractmethod
    def apply_strat(self):
        """For use for injecting strategies, by dictating removal"""
        pass

    @abstractmethod
    def add_states(self):
        pass

    @abstractmethod
    def add_weighted_edges(self):
        pass

    @abstractmethod
    def generate_defender(self) -> VITAMINDefender:
        """Final call to instantiate Vitamin Defender"""
        pass


class VulCGSBuilder(VITAMINDefenderBuilder):
    """
    VulCGS is a builder for VITAMINDefender that constructs a CGS with:

    Nodes corresponding to all the possible vulnerabilities defined in union of global vulnerability list and node-specific vulnerabilities

    Edges correspond to executing an exploit resulting in a certain outcome (defined in model.VulnerabilityOutcomes). The weights of the edge correspond to the countermeasure for that exploit, which is up to the discretion of the design (network_availability effect by reimaging target nodes, complete removal of vulnerability etc.)
    """
    def __init__(self, env: model.Environment, countermeasure_fn = countermeasures.ArbitraryCost(3).calculate_cost()) -> None:
        self.reset()
        self._env = env

        self._vulns = self._collect_all_node_vulnerabilities(env.nodes()) | env.vulnerability_library

        self._countermeasure_costs = dict([(k, countermeasure_fn(vuln)) for k, vuln in self._vulns.items()])
    def _collect_all_node_vulnerabilities(self, nodes: Iterator[Tuple[model.NodeID, model.NodeInfo]]) -> model.VulnerabilityLibrary:
        vulns = dict({})
        for _, n in nodes:
            for v_id, v in n.vulnerabilities.items():
                vulns[v_id] = v
        return vulns

    def reset(self):
        self._defender = VITAMINDefender()

    def add_states(self):
        self._defender.graph.add_nodes_from([(k, {"data": v}) for (k, v) in list(self._vulns.items())])
        return self

    def add_weighted_edges(self):
        return self

    def apply_strat(self):
        return self

    def generate_defender(self) -> VITAMINDefender:
        return self._defender
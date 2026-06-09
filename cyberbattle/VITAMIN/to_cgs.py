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
EXPORT_DIR = "cyberbattle/VITAMIN/vit-models"

class VITAMINDefender:
    """
    Chosen representation of the CGS
    """
    graph: nx.DiGraph
    strat: List[str] # state labels for removal
    initial_state: str
    acc_properties_indices: Set[str]
    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self.strat = []
    def export_to_vitamin(self, filename):
        """
        Write to file adjacency matrix in VITAMIN format (space-delimited)
        i.e. for nodes a -> b -> c and each node has a self loop:
        TODO: Add header transition with costs
        1 1 0
        0 1 1
        0 0 1

        # DESCRIPTION: Two agents; costs on actions. Traces are verified under cost
        # bounds; properties must hold within those bounds.

        Transition_With_Costs
        0 2 3 0 0 0
        0 0 2 1 0 0
        0 3 0 1 4 0
        0 0 0 0 3 5
        0 0 0 4 0 6
        0 0 0 0 0 *

        Name_State
        s0 s1 s2 s3 s4 s5
        Initial_State
        s0
        Atomic_propositions
        goal safe
        Labelling
        0 0
        1 0
        0 0
        1 0
        0 0
        1 1
        Number_of_agents
        2


        """
        states = self.graph.nodes()
        graph_array = nx.to_numpy_array(self.graph, None, dtype=int)
        # TODO: parse complete VITAMIN-compatible format
        with open(f"{os.getcwd()}/{EXPORT_DIR}/{filename}", 'w') as f:
            f.write("Transition_With_Costs" + '\n')
            for row in graph_array:
                f.write(' '.join(map(str, row)) + '\n')

            f.write("Name_State" + '\n')
            f.write(' '.join(self.get_cgs_states()))

            f.write("Initial_State" + '\n')
            f.write(self.get_initial_state())

            f.write("Number_of_agents" + '\n' + "2")
    def get_cgs_states(self):
        return list(self.graph.nodes().keys())
    def get_initial_state(self):
        return self.initial_state

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
    def specify_initial_state(self):
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

    Nodes corresponding to all the possible vulnerabilities defined in union of global vulnerability list and node-specific vulnerabilities. We eventually can associate atomic propositions with preventing these vulnerabilities, and expand beyond this according to certain node properties.

    TODO: export node_properties to support AP generation...

    Edges correspond to executing an exploit resulting in a certain outcome (defined in model.VulnerabilityOutcomes). The weights of the edge correspond to the countermeasure for that exploit, which is up to the discretion of the design (network_availability effect by reimaging target nodes, complete removal of vulnerability etc.)

    Best for small, manual networks with a workable list of vulnerabilities.
    """
    def __init__(self, env: model.Environment, countermeasure_calc) -> None:
        self.reset()
        self._env = env
        self._countermeasure_calc = countermeasure_calc
        self._vulns = self._collect_all_node_vulnerabilities(env.nodes()) | env.vulnerability_library

        # self._countermeasure_costs = dict([(k, countermeasure_fn(vuln)) for k, vuln in self._vulns.items()])

    def _collect_all_node_vulnerabilities(self, nodes: Iterator[Tuple[model.NodeID, model.NodeInfo]]) -> model.VulnerabilityLibrary:
        vulns = dict({})
        for _, n in nodes:
            for v_id, v in n.vulnerabilities.items():
                vulns[v_id] = v
        return vulns

    def _extra_states(self):
        pass

    def _extract_vulnerability_targets(self, vuln: model.VulnerabilityInfo):
        outcome = vuln.outcome
        if isinstance(outcome, model.LeakedNodesId):
            return outcome.nodes
        if isinstance(outcome, model.LeakedCredentials):
            return list(set(cred.node for cred in outcome.credentials))
        # prec = vuln.precondition TODO: check preconditions satisfied by properties, not required?
        return []

    def _extract_outcome_targets(self):
        pass


    def reset(self):
        self._defender = VITAMINDefender()

    def add_states(self):
        self._defender.graph.add_nodes_from([(k, {"data": v}) for (k, v) in list(self._vulns.items())])
        return self

    def specify_initial_state(self, vuln: model.VulnerabilityID):
        self._defender.initial_state = vuln
        return self

    def add_weighted_edges(self):

        for id, vuln in self._vulns.items():
            targets = self._extract_vulnerability_targets(vuln)

            possible_vulns = [id for id, vuln in self._vulns.items() for t in targets if id in self._env.get_node(t).vulnerabilities.keys()]

            for pos_vuln in possible_vulns:
                self._defender.graph.add_edge(id, pos_vuln, weight=self._countermeasure_calc.calculate_cost(id))
        return self

    def apply_strat(self):
        return self

    def generate_defender(self) -> VITAMINDefender:
        return self._defender
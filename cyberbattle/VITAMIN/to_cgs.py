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

import os

EXPORT_DIR = "vit-models"

class VITAMINDefender:
    """
    Chosen representation of the CGS
    """
    graph: nx.DiGraph

    def export_to_vitamin(self, filename):
        """
        Write to file adjacency matrix in VITAMIN format (space-delimited)
        i.e. for nodes a -> b -> c and each node has a self loop:

        1 1 0
        0 1 1
        0 0 1

        """
        graph_array = nx.to_numpy_array(self.graph, None, dtype=int)

        with open(f"{os.getcwd()}/{EXPORT_DIR}/{filename}", 'w') as f:
            for row in graph_array:
                f.write(' '.join(map(str, row)) + '\n')

    def inject_vitamin_strategy(self):
        pass

class VulCGS:
    def __init__(self, env: model.Environment, attacker: actions.AgentActions, defender: actions.DefenderAgentActions) -> None:
        pass
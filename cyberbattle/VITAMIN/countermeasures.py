"""
Module for implementing costs for a defender to actively mitigate a certain vulnerability
"""
import cyberbattle.simulation.model as model
import cyberbattle.simulation.actions as actions
from abc import ABC, abstractmethod
from typing import List

class CountermeasureCalculator(ABC):
    @abstractmethod
    def calculate_cost(self, edge):
        pass


class ArbitraryCost(CountermeasureCalculator):

    def __init__(self, cost) -> None:
        self._fixed_cost = cost

    def calculate_cost(self, edge):
        return self._fixed_cost

class ReimagingCountermeasure(CountermeasureCalculator):
    """
    Give total cost to the system derived from service calculation

    """
    def __init__(self, env: model.Environment) -> None:
        self._env = env
        self._defender_actions = actions.DefenderAgentActions(self._env)



    def calculate_cost(self, vuln: model.VulnerabilityID):

        self._execute_countermeasure(vuln)

        operational_capacity = self._calculate_service(0, 0, self._env.nodes())

        return operational_capacity

    def _execute_countermeasure(self, vuln: model.VulnerabilityID):

        for i, node in self._env.nodes():
            if vuln in node.vulnerabilities.keys():
                try:
                    self._defender_actions.reimage_node(i)
                except AssertionError: # TODO should we continue?
                    continue

    def _calculate_service(self, total_node_weights, network_node_availability, nodes):
        """
        Simplified calculation for keeping integer values
        """
        for node_id, node_info in nodes:
            total_service_weights = 0
            running_service_weights = 0
            for service in node_info.services:
                total_service_weights += service.sla_weight
                running_service_weights += service.sla_weight * int(service.running)

            if node_info.status == model.MachineStatus.Running:
                adjusted_node_availability = (1 + running_service_weights) / (1 + total_service_weights)
            else:
                adjusted_node_availability = 0.0

            network_node_availability += adjusted_node_availability * node_info.sla_weight
        return int(network_node_availability)
"""
Module for implementing costs for a defender to actively mitigate a certain vulnerability
"""
import cyberbattle.simulation.model as model
import cyberbattle.simulation.actions as actions
from abc import ABC, abstractmethod


class CountermeasureCalculator(ABC):
    @abstractmethod
    def calculate_cost(self):
        pass


class ArbitraryCost(CountermeasureCalculator):

    def __init__(self, cost) -> None:
        self._fixed_cost = cost

    def calculate_cost(self):
        return lambda _ : self._fixed_cost

class TotalDisruption(CountermeasureCalculator):
    """
    Give total cost to the system derived from service calculation

    """
    def __init__(self, env: model.Environment) -> None:
        self._env = env

    def calculate_cost():
        return self.__calculate_service(0, 0, self._env.nodes())

    def __calculate_service(self, total_node_weights, network_node_availability, nodes):
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

            total_node_weights += node_info.sla_weight
            network_node_availability += adjusted_node_availability * node_info.sla_weight
        return total_node_weights, network_node_availability
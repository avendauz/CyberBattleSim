"""
Unit tests for associating costs for a defender to execute a user-specified countermeasure against a certain vulnerability
"""
import pytest
import cyberbattle.VITAMIN.countermeasures as cm

def test_arbitrary() -> None:
    arbitrary = cm.ArbitraryCost(3)
    assert arbitrary.calculate_cost()("anything") == 3
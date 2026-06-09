import pytest
import cyberbattle.VITAMIN.to_cgs as to_cgs
import cyberbattle.simulation.actions as actions
import cyberbattle.simulation.model as model
from datetime import datetime, timezone
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
import networkx as nx
import cyberbattle.VITAMIN.countermeasures as cm
NODES = {
    "a": model.NodeInfo(
        services=[
            model.ListeningService("RDP"),
            model.ListeningService("HTTP"),
            model.ListeningService("HTTPS"),
        ],
        value=70,
        properties=list(["Windows", "Win10", "PortRDPOpen", "PortHTTPOpen", "PortHTTPsOpen"]),
        vulnerabilities=dict(
            ListNeighbors=model.VulnerabilityInfo(
                description="reveal other nodes",
                type=model.VulnerabilityType.LOCAL,
                outcome=model.LeakedNodesId(nodes=["b", "c", "dc"]),
            ),
            DumpCreds=model.VulnerabilityInfo(
                description="leaking some creds",
                type=model.VulnerabilityType.LOCAL,
                outcome=model.LeakedCredentials(
                    [
                        model.CachedCredential("Sharepoint", "HTTPS", "ADPrincipalCreds"),
                        model.CachedCredential("Sharepoint", "HTTPS", "cred"),
                    ]
                ),
            ),
        ),
        agent_installed=True,
    ),
    "b": model.NodeInfo(
        services=[model.ListeningService("SSH"), model.ListeningService("SQL")],
        value=80,
        properties=list(["Linux", "PortSSHOpen", "PortSQLOpen"]),
        agent_installed=False,
    ),
    "c": model.NodeInfo(
        services=[
            model.ListeningService("RDP"),
            model.ListeningService("HTTP"),
            model.ListeningService("HTTPS"),
        ],
        value=40,
        properties=list(["Windows", "Win10", "PortRDPOpen", "PortHTTPOpen", "PortHTTPsOpen"]),
        agent_installed=True,
    ),
    "dc": model.NodeInfo(
        services=[model.ListeningService("RDP"), model.ListeningService("WMI")],
        value=100,
        properties=list(["Windows", "Win10", "PortRDPOpen", "PortWMIOpen"]),
        agent_installed=False,
    ),
    "Sharepoint": model.NodeInfo(
        services=[model.ListeningService("HTTPS", allowedCredentials=["ADPrincipalCreds"])],
        value=100,
        properties=["SharepointLeakingPassword"],
        firewall=model.FirewallConfiguration(
            incoming=[
                model.FirewallRule(port="SSH", permission=model.RulePermission.ALLOW),
                model.FirewallRule(port="HTTPS", permission=model.RulePermission.ALLOW),
                model.FirewallRule(port="HTTP", permission=model.RulePermission.ALLOW),
                model.FirewallRule(port="RDP", permission=model.RulePermission.BLOCK),
            ],
            outgoing=[],
        ),
        vulnerabilities=dict(
            ScanSharepointParentDirectory=model.VulnerabilityInfo(
                description="Navigate to SharePoint site, browse parent " "directory",
                type=model.VulnerabilityType.REMOTE,
                outcome=model.LeakedCredentials(
                    credentials=[
                        model.CachedCredential(
                            node="AzureResourceManager",
                            port="HTTPS",
                            credential="ADPrincipalCreds",
                        )
                    ]
                ),
                rates=model.Rates(successRate=1.0),
                cost=1.0,
            )
        ),
    ),
    "AzureResourceManager": model.NodeInfo(
        services=[model.ListeningService("RDP"), model.ListeningService("WMI")],
        value=100,
        properties=list(["Windows", "Win10", "PortRDPOpen", "PortWMIOpen"]),
        agent_installed=False,
    ),
}
ADMINTAG = model.AdminEscalation().tag
SYSTEMTAG = model.SystemEscalation().tag

GLOBAL_VULNERABILITIES = {
    "UACME61": model.VulnerabilityInfo(
        description="UACME UAC bypass #61",
        type=model.VulnerabilityType.LOCAL,
        URL="https://github.com/hfiref0x/UACME",
        precondition=model.Precondition(f"Windows&Win10&(~({ADMINTAG}|{SYSTEMTAG}))"),
        outcome=model.AdminEscalation(),
        rates=model.Rates(0, 0.2, 1.0),
    ),
    "UACME67": model.VulnerabilityInfo(
        description="UACME UAC bypass #67 (fake system escalation) ",
        type=model.VulnerabilityType.LOCAL,
        URL="https://github.com/hfiref0x/UACME",
        precondition=model.Precondition(f"Windows&Win10&(~({ADMINTAG}|{SYSTEMTAG}))"),
        outcome=model.SystemEscalation(),
        rates=model.Rates(0, 0.2, 1.0),
    ),
    "MimikatzLogonpasswords": model.VulnerabilityInfo(
        description="Mimikatz sekurlsa::logonpasswords.",
        type=model.VulnerabilityType.LOCAL,
        URL="https://github.com/gentilkiwi/mimikatz",
        precondition=model.Precondition(f"Windows&({ADMINTAG}|{SYSTEMTAG})"),
        outcome=model.LeakedCredentials([]),
        rates=model.Rates(0, 1.0, 1.0),
    ),
    "RDPBF": model.VulnerabilityInfo(
        description="RDP Brute Force",
        type=model.VulnerabilityType.REMOTE,
        URL="https://attack.mitre.org/techniques/T1110/",
        precondition=model.Precondition("Windows&PortRDPOpen"),
        outcome=model.LateralMove(),
        rates=model.Rates(0, 0.2, 1.0),
        cost=1.0,
    ),
}

ENV_IDENTIFIERS = model.infer_constants_from_nodes(cast(Iterator[Tuple[model.NodeID, model.NodeInfo]], list(NODES.items())), dict([]))

# @pytest.fixture
# def simple_environment() -> model.Environment:

#     env = model.Environment(
#         network=model.create_network(NODES),
#         version=model.VERSION_TAG,
#         vulnerability_library=dict([]),
#         identifiers=ENV_IDENTIFIERS,
#         creationTime=datetime.utcnow(),
#         lastModified=datetime.utcnow(),
#     )
#     return env

@pytest.fixture
def simple_env() -> model.Environment:

    env = model.Environment(
        network=model.create_network(NODES),
        version=model.VERSION_TAG,
        vulnerability_library=GLOBAL_VULNERABILITIES,
        identifiers=ENV_IDENTIFIERS,
        creationTime=datetime.now(timezone.utc),
        lastModified=datetime.now(timezone.utc),
    )
    return env

"""
Unit tests for VulCGSBuilder
"""

def test_empty_builder(simple_env: model.Environment) -> None:
    defender = (to_cgs.VulCGSBuilder(simple_env)
                .generate_defender()
                )
    init_graph = nx.DiGraph()
    assert defender.graph.nodes == init_graph.nodes
    assert defender.graph.edges == init_graph.edges


def test_defender_vulns(simple_env: model.Environment) -> None:
    defender = (to_cgs.VulCGSBuilder(simple_env))

    assert defender._vulns["ScanSharepointParentDirectory"] == NODES["Sharepoint"].vulnerabilities["ScanSharepointParentDirectory"]
    assert defender._vulns["DumpCreds"] == NODES["a"].vulnerabilities["DumpCreds"]
    assert defender._vulns["ListNeighbors"] == NODES["a"].vulnerabilities["ListNeighbors"]
    for i, k in GLOBAL_VULNERABILITIES.items():
        assert defender._vulns[i] == k

def test_add_states(simple_env: model.Environment) -> None:
    defender = (to_cgs.VulCGSBuilder(simple_env)
                .add_states()
                .generate_defender()
                )
    assert defender.graph.has_node("ScanSharepointParentDirectory")
    assert defender.graph.has_node("DumpCreds")
    assert defender.graph.has_node("ListNeighbors")
    for i, _ in GLOBAL_VULNERABILITIES.items():
        assert defender.graph.has_node(i)

def test_add_weighted_edges(simple_env: model.Environment) -> None:
    defender = (to_cgs.VulCGSBuilder(simple_env)
                .add_states()
                .add_weighted_edges(cm.ArbitraryCost(3))
                .generate_defender())
    assert defender.graph.has_edge("DumpCreds", "ScanSharepointParentDirectory")

def test_initial_state(simple_env: model.Environment) -> None:
    initial_state = "DumpCreds"
    defender = (to_cgs.VulCGSBuilder(simple_env)
                .specify_initial_state(initial_state)
                .generate_defender())
    assert defender.initial_state == initial_state


"""
VITAMINDefender tests
"""

def test_export_to_vitamin(simple_env: model.Environment):
    defender = (to_cgs.VulCGSBuilder(simple_env)
                .add_states()
                .add_weighted_edges(cm.ReimagingCountermeasure(simple_env))
                .generate_defender())
    print("SHOULD BE EXPORTING")
    #defender.export_to_vitamin("temp.txt")
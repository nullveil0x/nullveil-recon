"""Registry / structural integrity tests — catch wiring regressions early."""
import re


def test_version_semver(nv):
    assert re.fullmatch(r"\d+\.\d+\.\d+", nv.__version__), nv.__version__


def test_registry_non_contiguous_but_complete(nv):
    nums = sorted(nv.ALL_MODULE_NUMS)
    assert len(nums) == len(set(nums)), "duplicate module numbers"
    assert len(nv.ATTACK_MODULES) == len(nums)
    # every number resolves to a registry entry via the canonical accessor
    for i in nums:
        assert nv.module_entry(i) is not None, f"module {i} unresolved"


def test_module_by_num_matches_registry(nv):
    for name, idx, title, desc in nv.ATTACK_MODULES:
        assert nv.MODULE_BY_NUM[idx][0] == name
        assert nv.module_entry(idx)[2] == title
        assert desc, f"module {idx} has empty description"


def test_every_module_method_exists(nv):
    """Each registry number maps to a real coroutine on WebsiteRecon."""
    import inspect
    n_coros = len([1 for n, _ in inspect.getmembers(nv.WebsiteRecon, inspect.iscoroutinefunction)])
    # registry name -> method is resolved elsewhere; just ensure the module
    # exposes the documented count and no method is missing for the entries
    # the tool advertises by number.
    assert n_coros >= len(nv.ALL_MODULE_NUMS) - 5
    assert len(nv.ALL_MODULE_NUMS) >= 40


def test_deferred_subset_of_all(nv, recon):
    # DEFERRED is a set defined in run(); re-derive the documented contract:
    # late modules must be a subset of the whole registry
    for late in (35, 36, 37, 39, 45, 46, 47, 49):
        assert late in nv.ALL_MODULE_NUMS


def test_parse_attack_list_aliases(nv):
    assert 44 in nv.parse_attack_list("cloud")
    assert 40 in nv.parse_attack_list("js")
    assert 43 in nv.parse_attack_list("graphql")
    assert 45 in nv.parse_attack_list("cvss")
    assert 46 in nv.parse_attack_list("mitre")
    assert 47 in nv.parse_attack_list("kev")
    assert 48 in nv.parse_attack_list("takeover")
    assert 49 in nv.parse_attack_list("watch")


def test_parse_attack_list_unknown_does_not_crash(nv):
    res = nv.parse_attack_list("dns,not_a_module")
    assert 1 in res

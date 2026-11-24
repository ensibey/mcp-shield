"""Regression test ensuring mcp-shield maintains 100% precision & recall on the MCP benchmark."""

from benchmarks.run_benchmark import run_benchmark


def test_mcp_security_benchmark_100_percent_f1():
    rep = run_benchmark()
    assert rep["total_cases"] >= 16
    assert rep["fp"] == 0
    assert rep["fn"] == 0
    assert rep["precision"] == 1.0
    assert rep["recall"] == 1.0
    assert rep["f1_score"] == 1.0
    assert rep["false_positive_rate"] == 0.0

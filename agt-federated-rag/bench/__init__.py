"""Benchmark harnesses for the AGT Federated-RAG governed tool path.

Dependency-light, hermetic micro-benchmarks (no network, no live services) that quantify
the cost of the governance gates. Run with ``RAG_ENV_FILE=__none__`` so they construct
``Settings`` without a .env (same hermetic contract as the test suite).
"""

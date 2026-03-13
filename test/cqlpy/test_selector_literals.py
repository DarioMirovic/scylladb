# -*- coding: utf-8 -*-
# Copyright 2026-present ScyllaDB
#
# SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0

# Tests literals in the SELECT clause.
#
# Originally, the CQL grammar allowed literals (constants, bind markers, and
# collections/tuples/UDTs of literals) only in the WHERE clause. This test suite
# tests literals in the SELECT clause, which were added later [1].
#
# Scalar literals (integers, strings, floats, etc.) and tuples work with
# inferred types. Maps, lists, and bind markers require explicit type context.
#
# [1]: https://scylladb.atlassian.net/browse/SCYLLADB-296

from contextlib import contextmanager
import uuid
import pytest
from .util import unique_name, new_function
from .conftest import scylla_only
from cassandra.protocol import InvalidRequest

want_lua = scylla_only

def test_simple_literal_selectors(cql, test_keyspace, want_lua):
    @contextmanager
    def new_sum_function(name: str, type: str, op: str):
        body = f"(i {type}, j {type}) RETURNS NULL ON NULL INPUT RETURNS {type} LANGUAGE lua AS 'return i {op} j;'"
        with new_function(cql, test_keyspace, body, name=name, args=f"{type}, {type}") as f:
            yield f

    # Create two different functions with the same name fun, but a
    # different signature (different parameters):
    fun = unique_name()
    ksfun = f"{test_keyspace}.{fun}"
    with new_sum_function(name=fun, type="int", op="+"):
        rows = cql.execute(f"SELECT {ksfun}(1, 2) AS sum_int FROM system.local")
        assert rows.one().sum_int == 3
        stmt = cql.prepare(f"SELECT {ksfun}(?, ?) AS sum_int FROM system.local")
        rows = cql.execute(stmt, (10, 20))
        assert rows.one().sum_int == 30
        with pytest.raises(InvalidRequest, match="Type error"):
            cql.execute(f"SELECT {ksfun}(1, 'asf') AS sum_int FROM system.local")
    with new_sum_function(name=fun, type="text", op=".."):
        rows = cql.execute(f"SELECT {ksfun}('hello, ', 'world!') AS sum_text FROM system.local")
        assert rows.one().sum_text == "hello, world!"
        stmt = cql.prepare(f"SELECT {ksfun}(?, ?) AS sum_text FROM system.local")
        rows = cql.execute(stmt, ('foo', 'bar'))
        assert rows.one().sum_text == "foobar"
        with pytest.raises(InvalidRequest, match="Type error"):
            cql.execute(f"SELECT {ksfun}('asf', 1) AS sum_text FROM system.local")

# scylla-only due to set_intersection function
def test_set_literal_selector(cql, test_keyspace, scylla_only):
    cql.execute(f"CREATE TABLE IF NOT EXISTS {test_keyspace}.sets (id int PRIMARY KEY, vals set<int>, vals2 set<frozen<map<text, int>>>)")
    cql.execute(f"INSERT INTO {test_keyspace}.sets (id, vals) VALUES (1, {{1, 2, 3, 4, 5}})")
    rows = cql.execute(f"SELECT set_intersection(vals, {{3,4,5,6,7}}) AS intersection FROM {test_keyspace}.sets WHERE id=1")
    assert rows.one().intersection == {3,4,5}

    cql.execute(f"INSERT INTO {test_keyspace}.sets (id, vals2) VALUES (1, {{ {{ 'aa': 1, 'bb': 2 }}, {{ 'cc': 3, 'dd': 4 }} }})")
    rows = cql.execute(f"SELECT set_intersection(vals2, {{ {{ 'cc': 3, 'dd': 4 }}, {{ 'cc': 3, 'dd': 5 }} }}) AS intersection FROM {test_keyspace}.sets WHERE id=1")
    assert rows.one().intersection == {frozenset([('cc', 3), ('dd', 4)])}

# Test that scalars and tuples work with inferred types in SELECT.
def test_inferred_type_literal_selectors(cql, test_keyspace):
    rows = cql.execute("SELECT 1 AS v FROM system.local")
    assert rows.one().v == 1
    rows = cql.execute("SELECT 1.5 AS v FROM system.local")
    assert rows.one().v == 1.5
    rows = cql.execute("SELECT 'hello' AS v FROM system.local")
    assert rows.one().v == 'hello'
    rows = cql.execute("SELECT true AS v FROM system.local")
    assert rows.one().v == True
    rows = cql.execute("SELECT 123e4567-e89b-12d3-a456-426614174000 AS v FROM system.local")
    assert rows.one().v == uuid.UUID('123e4567-e89b-12d3-a456-426614174000')
    rows = cql.execute("SELECT 0xdeadbeef AS v FROM system.local")
    assert rows.one().v == bytes.fromhex('deadbeef')
    rows = cql.execute("SELECT 1mo AS v FROM system.local")
    assert rows.one().v is not None
    # Tuple element types are inferred individually.
    rows = cql.execute("SELECT (1, 'a', 3.0) AS tpl FROM system.local")
    assert rows.one().tpl == (1, 'a', 3.0)

# Test SELECT without a FROM clause. Cassandra does not support this syntax,
# so these tests are Scylla-only.
def test_select_without_from(cql, test_keyspace, scylla_only):
    rows = cql.execute("SELECT 1 AS one")
    assert rows.one().one == 1
    rows = cql.execute("SELECT 'hello' AS greeting")
    assert rows.one().greeting == 'hello'
    rows = cql.execute("SELECT now() AS t")
    assert rows.one().t is not None
    rows = cql.execute("SELECT toTimestamp(now()) AS ts")
    assert rows.one().ts is not None
    rows = cql.execute("SELECT 1 AS one, 'hi' AS greeting")
    row = rows.one()
    assert row.one == 1
    assert row.greeting == 'hi'
    with pytest.raises(InvalidRequest, match="FROM"):
        cql.execute("SELECT *")
    with pytest.raises(InvalidRequest, match="resolve column"):
        cql.execute("SELECT col")

# Test that literals which cannot have their type inferred fail as expected.
def test_literal_type_inference_failure(cql, test_keyspace):
    # Maps and lists require explicit element type context.
    with pytest.raises(InvalidRequest, match="infer type"):
        cql.execute("SELECT { 'a': 1, 'b': 2 } AS mp FROM system.local")
    with pytest.raises(InvalidRequest, match="infer type"):
        cql.execute("SELECT [1, 2, 3] AS lst FROM system.local")
    # Bind markers have no type info at all.
    with pytest.raises(InvalidRequest, match="infer type"):
        cql.execute("SELECT ? AS qm FROM system.local")
    with pytest.raises(InvalidRequest, match="infer type"):
        cql.execute("SELECT :bindvar AS bv FROM system.local")

# Test that count(2) fails as expected. We're likely to relax this restriction later
# as it is quite artificial. scylla_only because Cassandra does allow it.
def test_count_literal_only_1(cql, test_keyspace, scylla_only):
    with pytest.raises(InvalidRequest, match="expects a column or the literal 1 as an argument"):
        cql.execute("SELECT count(2) AS cnt FROM system.local")
    # Error message here is not the best, but tightening error messages
    # here is quite a hassle and we plan to relax the restriction later anyway.
    with pytest.raises(InvalidRequest, match="only valid when argument types are known"):
        cql.execute("SELECT count(?) AS cnt FROM system.local")

/*
 * Copyright (C) 2026-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "cql3/statements/select_no_from_statement.hh"
#include "cql3/statements/raw/select_no_from_statement.hh"
#include "cql3/statements/prepared_statement.hh"
#include "cql3/selection/raw_selector.hh"
#include "cql3/expr/expr-utils.hh"
#include "cql3/expr/evaluate.hh"
#include "cql3/expr/expression.hh"
#include "cql3/result_set.hh"
#include "cql3/query_options.hh"
#include "cql3/column_identifier.hh"
#include "service/query_state.hh"
#include "service/client_state.hh"
#include "transport/messages/result_message.hh"
#include "audit/audit.hh"
#include "timeout_config.hh"
#include "exceptions/exceptions.hh"

namespace cql3 {

namespace statements {

select_no_from_statement::select_no_from_statement(
        uint32_t bound_terms,
        std::vector<expr::expression> exprs,
        std::vector<lw_shared_ptr<column_specification>> column_specs)
    : cql_statement(&timeout_config::other_timeout)
    , _bound_terms(bound_terms)
    , _exprs(std::move(exprs))
    , _column_specs(std::move(column_specs))
    , _result_metadata(::make_shared<const metadata>(_column_specs))
{}

uint32_t select_no_from_statement::get_bound_terms() const {
    return _bound_terms;
}

::shared_ptr<const metadata> select_no_from_statement::get_result_metadata() const {
    return _result_metadata;
}

future<> select_no_from_statement::check_access(query_processor&, const service::client_state& state) const {
    state.validate_login();
    return make_ready_future<>();
}

bool select_no_from_statement::depends_on(std::string_view, std::optional<std::string_view>) const {
    return false;
}

future<::shared_ptr<cql_transport::messages::result_message>>
select_no_from_statement::execute(query_processor&, service::query_state&, const query_options& options,
        std::optional<service::group0_guard>) const {
    auto rs = std::make_unique<result_set>(_column_specs);
    std::vector<bytes_opt> row;
    row.reserve(_exprs.size());
    for (const auto& expr : _exprs) {
        row.push_back(std::move(expr::evaluate(expr, options)).to_bytes_opt());
    }
    rs->add_row(std::move(row));
    return make_ready_future<::shared_ptr<cql_transport::messages::result_message>>(
            ::make_shared<cql_transport::messages::result_message::rows>(cql3::result(std::move(rs))));
}

namespace raw {

select_no_from_statement::select_no_from_statement(
        std::vector<::shared_ptr<cql3::selection::raw_selector>> select_clause)
    : _select_clause(std::move(select_clause))
{}

std::unique_ptr<prepared_statement> select_no_from_statement::prepare(data_dictionary::database db, cql_stats&) {
    if (_select_clause.empty()) {
        throw exceptions::invalid_request_exception("SELECT * is not allowed without a FROM clause");
    }

    std::vector<expr::expression> exprs;
    std::vector<lw_shared_ptr<column_specification>> specs;
    exprs.reserve(_select_clause.size());
    specs.reserve(_select_clause.size());

    for (const auto& raw : _select_clause) {
        auto prepared = expr::prepare_expression(raw->selectable_, db, "", nullptr, nullptr);

        auto type = expr::type_of(prepared);
        if (!type) {
            throw exceptions::invalid_request_exception(
                    fmt::format("Cannot determine type of expression: {}", prepared));
        }

        sstring col_name = raw->alias ? raw->alias->to_string() : sstring("?");
        specs.push_back(make_lw_shared<column_specification>(
                "", "", ::make_shared<column_identifier>(col_name, true), type));
        exprs.push_back(std::move(prepared));
    }

    auto bound_terms = _prepare_ctx.bound_variables_size();
    auto stmt = ::make_shared<cql3::statements::select_no_from_statement>(
            bound_terms, std::move(exprs), std::move(specs));

    return std::make_unique<prepared_statement>(audit_info(), std::move(stmt), _prepare_ctx, std::vector<uint16_t>{});
}

audit::statement_category select_no_from_statement::category() const {
    return audit::statement_category::QUERY;
}

audit::audit_info_ptr select_no_from_statement::audit_info() const {
    return audit::audit::create_audit_info(category(), "", "");
}

} // namespace raw

} // namespace statements

} // namespace cql3

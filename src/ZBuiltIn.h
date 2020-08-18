// See the file "COPYING" in the main distribution directory for copyright.

// ZAM compiler declarations for built-in functions.
//
// This file is only included by ZAM.h, in the context of the ZAM class
// declaration.

// If the given expression corresponds to a call to a ZAM built-in,
// then compiles the call and returns true.  Otherwise, returns false.
bool IsZAM_BuiltIn(const Expr* e);

// Built-ins return true if able to compile the call, false if not.
bool BuiltIn_to_lower(const NameExpr* n, const expr_list& args);
bool BuiltIn_sub_bytes(const NameExpr* n, const expr_list& args);
bool BuiltIn_Log__write(const NameExpr* n, const expr_list& args);
bool BuiltIn_Broker__flush_logs(const NameExpr* n, const expr_list& args);
bool BuiltIn_get_port_etc(const NameExpr* n, const expr_list& args);
bool BuiltIn_reading_live_traffic(const NameExpr* n, const expr_list& args);
bool BuiltIn_reading_traces(const NameExpr* n, const expr_list& args);
bool BuiltIn_strstr(const NameExpr* n, const expr_list& args);
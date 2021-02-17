// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/Val.h"
#include "zeek/File.h"
#include "zeek/Func.h"
#include "zeek/OpaqueVal.h"
#include "zeek/Reporter.h"
#include "zeek/Desc.h"

using namespace zeek;

bool ZVal::zval_error_status = false;

bool zeek::IsManagedType(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case zeek::TYPE_ADDR:
	case zeek::TYPE_ANY:
	case zeek::TYPE_FILE:
	case zeek::TYPE_FUNC:
	case zeek::TYPE_LIST:
	case zeek::TYPE_OPAQUE:
	case zeek::TYPE_PATTERN:
	case zeek::TYPE_RECORD:
	case zeek::TYPE_STRING:
	case zeek::TYPE_SUBNET:
	case zeek::TYPE_TABLE:
	case zeek::TYPE_TYPE:
	case zeek::TYPE_VECTOR:
		return true;

	default:
		return false;

	}
	}


ZVal::ZVal(ValPtr v, const TypePtr& t)
	{
	if ( ! v )
		{
		// This can happen for some forms of error propagation.
		// We can deal with it iff the type is managed, and thus
		// we can employ a "nil" placeholder.
		ASSERT(IsManagedType(t));
		v = nullptr;
		return;
		}

	auto vt = v->GetType();

	if ( vt->Tag() != t->Tag() && t->Tag() != TYPE_ANY )
		{
		if ( t->InternalType() == TYPE_INTERNAL_OTHER ||
		     t->InternalType() != vt->InternalType() )
			reporter->InternalError("type inconsistency in ZVal constructor");
		}

	switch ( t->Tag() ) {
	case TYPE_BOOL:
		var = static_cast<BoolVal*>(v.release());
		break;
	case TYPE_INT:
		var = static_cast<IntVal*>(v.release());
		break;
	case TYPE_ENUM:
		var = static_cast<EnumVal*>(v.release());
		break;
	case TYPE_COUNT:
		var = static_cast<CountVal*>(v.release());
		break;
	case TYPE_PORT:
		var = static_cast<PortVal*>(v.release());
		break;
	case TYPE_DOUBLE:
		var = static_cast<DoubleVal*>(v.release());
		break;
	case TYPE_INTERVAL:
		var = static_cast<IntervalVal*>(v.release());
		break;
	case TYPE_TIME:
		var = static_cast<TimeVal*>(v.release());
		break;
	case TYPE_FUNC:
		var = static_cast<FuncVal*>(v.release());
		break;
	case TYPE_FILE:
		var = static_cast<FileVal*>(v.release());
		break;
	case TYPE_LIST:
		var = static_cast<ListVal*>(v.release());
		break;
	case TYPE_OPAQUE:
		var = static_cast<OpaqueVal*>(v.release());
		break;
	case TYPE_PATTERN:
		var = static_cast<PatternVal*>(v.release());
		break;
	case TYPE_TABLE:
		var = static_cast<TableVal*>(v.release());
		break;
	case TYPE_VECTOR:
		{
		var = static_cast<VectorVal*>(v.release());

		// Some run-time type-checking, sigh.
		auto my_ytag = t->AsVectorType()->Yield()->Tag();
		auto v_ytag = vt->AsVectorType()->Yield()->Tag();

		if ( my_ytag != v_ytag && my_ytag != TYPE_ANY &&
		     v_ytag != TYPE_ANY )
			{
			// Despite the above checks, this clash can still
			// happen thanks to the intercession of vector-of-any,
			// which for example can allow a function to return
			// a concrete vector-of-X that's assigned to a local
			// with a concrete vector-of-Y type.
			reporter->Error("vector type clash: %s vs. %s (%s)",
					type_name(my_ytag), type_name(v_ytag),
					obj_desc(v.get()).c_str());
			zval_error_status = true;
			}

		break;
		}

	case TYPE_RECORD:
		var = static_cast<RecordVal*>(v.release());
		break;
	case TYPE_STRING:
		var = static_cast<StringVal*>(v.release());
		break;
	case TYPE_ADDR:
		var = static_cast<AddrVal*>(v.release());
		break;
	case TYPE_SUBNET:
		var = static_cast<SubNetVal*>(v.release());
		break;
	case TYPE_ANY:
		var = static_cast<Val*>(v.release());
		break;
	case TYPE_TYPE:
		var = static_cast<TypeVal*>(v.release());
		break;

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad type in ZVal constructor");
	}
	}

ValPtr ZVal::ToVal(const TypePtr& t) const
	{
	Val* v;

	switch ( t->Tag() ) {
	case TYPE_INT:
		return {NewRef(), std::get<IntVal*>(var)};

	case TYPE_BOOL:
		return {NewRef(), std::get<BoolVal*>(var)};

	case TYPE_PORT:
		return {NewRef(), std::get<PortVal*>(var)};

	case TYPE_COUNT:
		return {NewRef(), std::get<CountVal*>(var)};

	case TYPE_DOUBLE:
		return {NewRef(), std::get<DoubleVal*>(var)};

	case TYPE_INTERVAL:
		return {NewRef(), std::get<IntervalVal*>(var)};

	case TYPE_TIME:
		return {NewRef(), std::get<TimeVal*>(var)};

	case TYPE_ENUM:
		return {NewRef(), std::get<EnumVal*>(var)};

	case TYPE_ANY:
		{
		int index = var.index();
		switch ( index )
			{
			case 0: return {NewRef(), std::get<AddrVal*>(var)};
			case 1: return {NewRef(), std::get<BoolVal*>(var)};
			case 2: return {NewRef(), std::get<CountVal*>(var)};
			case 3: return {NewRef(), std::get<DoubleVal*>(var)};
			case 4: return {NewRef(), std::get<EnumVal*>(var)};
			case 5: return {NewRef(), std::get<FileVal*>(var)};
			case 6: return {NewRef(), std::get<FuncVal*>(var)};
			case 7: return {NewRef(), std::get<IntVal*>(var)};
			case 8: return {NewRef(), std::get<IntervalVal*>(var)};
			case 9: return {NewRef(), std::get<ListVal*>(var)};
			case 10: return {NewRef(), std::get<OpaqueVal*>(var)};
			case 11: return {NewRef(), std::get<PatternVal*>(var)};
			case 12: return {NewRef(), std::get<PortVal*>(var)};
			case 13: return {NewRef(), std::get<RecordVal*>(var)};
			case 14: return {NewRef(), std::get<StringVal*>(var)};
			case 15: return {NewRef(), std::get<SubNetVal*>(var)};
			case 16: return {NewRef(), std::get<TableVal*>(var)};
			case 17: return {NewRef(), std::get<TimeVal*>(var)};
			case 18: return {NewRef(), std::get<TypeVal*>(var)};
			case 19: return {NewRef(), std::get<Val*>(var)};
			case 20: return {NewRef(), std::get<VectorVal*>(var)};
			default: return nullptr;
			}
		}
		break;

	case TYPE_TYPE:
		return {NewRef(), std::get<TypeVal*>(var)};

	case TYPE_FUNC:
		return {NewRef(), std::get<FuncVal*>(var)};

	case TYPE_FILE:
		return {NewRef(), std::get<FileVal*>(var)};

	case TYPE_ADDR:		return {NewRef(), std::get<AddrVal*>(var)};
	case TYPE_SUBNET:	return {NewRef(), std::get<SubNetVal*>(var)};
	case TYPE_STRING:	return {NewRef(), std::get<StringVal*>(var)};
	case TYPE_LIST:		return {NewRef(), std::get<ListVal*>(var)};
	case TYPE_OPAQUE:	return {NewRef(), std::get<OpaqueVal*>(var)};
	case TYPE_TABLE:	return {NewRef(), std::get<TableVal*>(var)};
	case TYPE_RECORD:	return {NewRef(), std::get<RecordVal*>(var)};
	case TYPE_VECTOR:	return {NewRef(), std::get<VectorVal*>(var)};
	case TYPE_PATTERN:	return {NewRef(), std::get<PatternVal*>(var)};

	case TYPE_ERROR:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		reporter->InternalError("bad ret type return tag");
	}

	reporter->Error("value used but not set");
	zval_error_status = true;

	return nullptr;
	}

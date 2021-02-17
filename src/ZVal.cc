// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
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
	case TYPE_INT:
	case TYPE_ENUM:
		var = v->AsInt();
		break;

	case TYPE_COUNT:
		var = v->AsCount();
		break;

	case TYPE_PORT:
		var = v.release()->AsPortVal();
		break;

	case TYPE_DOUBLE:
	case TYPE_INTERVAL:
	case TYPE_TIME:
		var = v->AsDouble();
		break;

	case TYPE_FUNC:
		{
		Func* f = v->AsFunc();
		var = f;
		Ref(f);
		break;
		}

	case TYPE_FILE:
		{
		File* f = v->AsFile();
		var = f;
		Ref(f);
		break;
		}

	case TYPE_LIST:
		var = v.release()->AsListVal();
		break;

	case TYPE_OPAQUE:
		var = v.release()->AsOpaqueVal();
		break;

	case TYPE_PATTERN:
		var = v.release()->AsPatternVal();
		break;

	case TYPE_TABLE:
		var = v.release()->AsTableVal();
		break;

	case TYPE_VECTOR:
		{
		var = v.release()->AsVectorVal();

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
		var = v.release()->AsRecordVal();
		break;

	case TYPE_STRING:
		var = v.release()->AsStringVal();
		break;

	case TYPE_ADDR:
		var = v.release()->AsAddrVal();
		break;

	case TYPE_SUBNET:
		var = v.release()->AsSubNetVal();
		break;

	case TYPE_ANY:
		var = static_cast<Val*>(v.release());
		break;

	case TYPE_TYPE:
		var = t->Ref();
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
		return val_mgr->Int(std::get<bro_int_t>(var));

	case TYPE_BOOL:
		return val_mgr->Bool(std::get<bro_int_t>(var) ? true : false);

	case TYPE_PORT:
		return {NewRef(), std::get<PortVal*>(var)};

	case TYPE_COUNT:
		return val_mgr->Count(std::get<bro_uint_t>(var));

	case TYPE_DOUBLE:
		return make_intrusive<DoubleVal>(std::get<double>(var));

	case TYPE_INTERVAL:
		return make_intrusive<IntervalVal>(std::get<double>(var), Seconds);

	case TYPE_TIME:
		return make_intrusive<TimeVal>(std::get<double>(var));

	case TYPE_ENUM:
		return t->AsEnumType()->GetEnumVal(std::get<bro_int_t>(var));

	case TYPE_ANY:
		{
		int index = var.index();
		switch ( index )
			{
			case 3: return {NewRef(), std::get<StringVal*>(var)};
			case 4: return {NewRef(), std::get<AddrVal*>(var)};
			case 5: return {NewRef(), std::get<SubNetVal*>(var)};
			case 8: return {NewRef(), std::get<ListVal*>(var)};
			case 9: return {NewRef(), std::get<OpaqueVal*>(var)};
			case 10: return {NewRef(), std::get<PatternVal*>(var)};
			case 11: return {NewRef(), std::get<TableVal*>(var)};
			case 12: return {NewRef(), std::get<RecordVal*>(var)};
			case 13: return {NewRef(), std::get<VectorVal*>(var)};
			case 14:
				{
				TypePtr tp = {NewRef{}, std::get<Type*>(var)};
				return make_intrusive<TypeVal>(tp);
				}
			case 15: return {NewRef(), std::get<Val*>(var)};
			default: return nullptr;
			}

		// std::variant<bro_int_t, bro_uint_t, double, StringVal*, AddrVal*, SubNetVal*,
		//              File*, Func*, ListVal*, OpaqueVal*, PatternVal*, TableVal*,
		//              RecordVal*, VectorVal*, Type*, Val*, Obj*, PortVal*> var;
		}

	case TYPE_TYPE:
		{
		TypePtr tp = {NewRef{}, std::get<Type*>(var)};
		return make_intrusive<TypeVal>(tp);
		}

	case TYPE_FUNC:
		{
		if ( Func* f = std::get<Func*>(var) )
			{
			FuncPtr fv_ptr = {NewRef{}, f};
			return make_intrusive<FuncVal>(fv_ptr);
			}
		}

		return nullptr;

	case TYPE_FILE:
		if ( File* f = std::get<File*>(var) )
			{
			FilePtr fv_ptr = {NewRef{}, f};
			return make_intrusive<FileVal>(fv_ptr);
			}

		return nullptr;

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

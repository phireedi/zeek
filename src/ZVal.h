// See the file "COPYING" in the main distribution directory for copyright.

// Low-level representation of Zeek scripting values.

#pragma once

#include <variant>

#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(AddrVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(BoolVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(CountVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(DoubleVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(EnumVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(FileVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(FuncVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(IntVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(IntervalVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(ListVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(OpaqueVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(PatternVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(PortVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(StringVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(SubNetVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableEntryVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TableVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TimeVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TypeVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(VectorVal, zeek);

namespace zeek {

// Note that a ZVal by itself is ambiguous: it doesn't track its type.
// This makes them consume less memory and cheaper to copy.  It does
// however require a separate way to determine the type.  Generally
// this is doable using surrounding context, or can be statically
// determined in the case of optimization/compilation.
//
// An alternative would be to use std::variant, but it will be larger
// due to needing to track the variant type, and it won't allow access
// to the managed_val member, which both simplifies memory management
// and is also required for sharing of ZAM frame slots.

class ZVal {

public:

	// Constructor for hand-populating the values.
	ZVal() = default;

	// Construct from a given higher-level script value with a given type.
	ZVal(ValPtr v, const TypePtr& t);

	// Convert to a higher-level script value.  The caller needs to
	// ensure that they're providing the correct type.
	ValPtr ToVal(const TypePtr& t) const;

	// Whether a low-level ZVal error has occurred.  Used to generate
	// run-time error messages.
	static bool ZValErrorStatus()		{ return zval_error_status; }

	// Resets the notion of low-level-error-occurred.
	static void ClearZValErrorStatus()	{ zval_error_status = false; }

	friend void DeleteManagedType(ZVal& v);

	std::variant<AddrVal*,
	             BoolVal*,
	             CountVal*,
	             DoubleVal*,
	             EnumVal*,
	             FileVal*,
	             FuncVal*,
	             IntVal*,
	             IntervalVal*,
	             ListVal*,
	             OpaqueVal*,
	             PatternVal*,
	             PortVal*,
	             RecordVal*,
	             StringVal*,
	             SubNetVal*,
	             TableVal*,
	             TimeVal*,
	             TypeVal*,
	             Val*,
	             VectorVal*> var;

	// A class-wide status variable set to true when a run-time
	// error associated with ZVal's occurs.  Static because often
	// the caller won't have direct access to the particular ZVal
	// that experienced the error, and just wants to know whether
	// *some* error has occurred.
	static bool zval_error_status;
};

// True if a given type is one for which we manage the associated
// memory internally.
bool IsManagedType(const TypePtr& t);

// Deletes a managed value.  Caller needs to ensure that the ZVal
// indeed holds such.
inline void DeleteManagedType(ZVal& v)
	{
	// auto o = std::get<Obj*>(v);
	// Unref(o);
	}

// Deletes a possibly-managed value.
inline void DeleteIfManaged(ZVal& v, const TypePtr& t)
	{
	if ( IsManagedType(t) )
		DeleteManagedType(v);
	}

} // zeek

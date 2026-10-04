#include "Core/Utility/Header/PrecompiledHeader.h"

#include "System/Symbol/Offsets/DynamicOffsets.h"
#include "System/Symbol/Parser/SymbolParser.h"

// Disassemble a native syscall stub to find its return-address offset.
// Win11 x64 ntdll stubs share the shape:
//   mov r10,rcx / mov eax,imm32 / test dword ptr [SharedUserData+0x308],1
//   jnz rel8 / syscall (0F 05) / ret (C3 or C2 xx xx)
// While a thread sits in the kernel wait, its user-mode Rip equals the
// address of that trailing ret. The old code hardcoded func+0x14; here the
// ret is located by scanning the first 64 bytes so future stub growth or
// padding never silently breaks alertable-thread scoring.
DWORD DisassembleWaitReturnOffset(void * FunctionBase, DWORD & OffsetOut)
{
	OffsetOut = 0;
	if (!FunctionBase)
	{
		return SYMBOL_ERR_INVALID_SYMBOL_NAME;
	}
	BYTE bytes[64]{ 0 };
	SIZE_T got = 0;
	// Direct memcpy would AV on a guard page; ReadProcessMemory on our own
	// process is the safe copy primitive here.
	if (!ReadProcessMemory(GetCurrentProcess(), FunctionBase, bytes, sizeof(bytes), &got) || got < 8)
	{
		return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
	}
	const size_t avail = static_cast<size_t>(got);
	for (size_t i = 0; i + 1 < avail; ++i)
	{
		if (bytes[i] != 0x0F || bytes[i + 1] != 0x05)
		{
			continue;
		}
		// syscall at i; ret must follow within 16 bytes (normally +2).
		for (size_t j = i + 2; j < avail && j < i + 2 + 16; ++j)
		{
			if (bytes[j] == 0xC3)
			{
				OffsetOut = static_cast<DWORD>(j);
				LOG(2, "Wait stub %p: syscall@+%zu ret@+%zu\n", FunctionBase, i, j);
				return SYMBOL_ERR_SUCCESS;
			}
			if (bytes[j] == 0xC2 && j + 2 < avail)
			{
				OffsetOut = static_cast<DWORD>(j);
				LOG(2, "Wait stub %p: syscall@+%zu ret imm16@+%zu\n", FunctionBase, i, j);
				return SYMBOL_ERR_SUCCESS;
			}
		}
	}
	LOG(1, "Wait stub %p: no syscall/ret pattern in %zu bytes\n", FunctionBase, avail);
	return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
}

// Same as REQUIRE_FIELD but accepts an older and a newer PDB spelling of the
// same field. Microsoft renames fields across builds without moving them; the
// field is still mandatory, so a type that carries neither name fails closed.
static DWORD ResolveFieldEither(const char * const * types, size_t typeCount, const char * primary, const char * alternate, DWORD & out)
{
	DWORD off = 0;
	if (sym_parser.GetFieldOffsetAny(types, typeCount, primary, off) == SYMBOL_ERR_SUCCESS)
	{
		out = off;
		return SYMBOL_ERR_SUCCESS;
	}
	if (sym_parser.GetFieldOffsetAny(types, typeCount, alternate, off) == SYMBOL_ERR_SUCCESS)
	{
		out = off;
		return SYMBOL_ERR_SUCCESS;
	}
	return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
}

DWORD ResolveDynamicOffsets()
{
	if (g_DynamicOffsets.Ready)
	{
		return SYMBOL_ERR_SUCCESS;
	}

	DYNAMIC_NT_OFFSETS tmp{};

	static const char * kTeb[] = { "TEB", "_TEB" };
	static const char * kPeb[] = { "PEB", "_PEB" };
	static const char * kKuser[] = { "_KUSER_SHARED_DATA", "KUSER_SHARED_DATA" };
	static const char * kLdrEntry[] = { "_LDR_DATA_TABLE_ENTRY", "LDR_DATA_TABLE_ENTRY" };
	static const char * kDdag[] = { "_LDR_DDAG_NODE", "LDR_DDAG_NODE" };
	// Inverted function table. 26xxx renamed the types and their fields while
	// keeping the exact same on-disk layout (see NTDefinitions.h): the table
	// became _INVERTED_FUNCTION_TABLE_USER_MODE {CurrentSize,MaximumSize,
	// Epoch,Overflow,TableEntry} and the entry became
	// _INVERTED_FUNCTION_TABLE_ENTRY {union{FunctionTable,DynamicTable},
	// ImageBase,SizeOfImage,SizeOfTable}. Both spellings are attempted below;
	// the layout is still required to be present, so this stays fail-closed.
	static const char * kInvTable[] = { "_RTL_INVERTED_FUNCTION_TABLE", "RTL_INVERTED_FUNCTION_TABLE", "_INVERTED_FUNCTION_TABLE_USER_MODE", "INVERTED_FUNCTION_TABLE_USER_MODE" };
	static const char * kInvEntry[] = { "_RTL_INVERTED_FUNCTION_TABLE_ENTRY", "RTL_INVERTED_FUNCTION_TABLE_ENTRY", "_INVERTED_FUNCTION_TABLE_ENTRY", "INVERTED_FUNCTION_TABLE_ENTRY" };
	static const char * kTls[] = { "_TLS_ENTRY", "TLS_ENTRY", "_LDRP_TLS_ENTRY", "LDRP_TLS_ENTRY" };
	static const char * kPathCtx[] = { "_LDRP_PATH_SEARCH_CONTEXT", "LDRP_PATH_SEARCH_CONTEXT" };
	static const char * kThreadState[] = { "_KTHREAD_STATE", "KTHREAD_STATE" };
	static const char * kWaitReason[] = { "_KWAIT_REASON", "KWAIT_REASON" };

#define REQUIRE_FIELD(types, field, out) \
	do { \
		DWORD _off = 0; \
		DWORD _r = sym_parser.GetFieldOffsetAny(types, _countof(types), field, _off); \
		if (_r != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: missing %s (tried %s)\n", field, types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
		(out) = _off; \
	} while (0)

// Same as REQUIRE_FIELD but accepts an older and a newer PDB spelling of the
// same field. Microsoft renames fields across builds without moving them; the
// field is still mandatory, so a type that carries neither name fails closed.
#define REQUIRE_FIELD_ALT(types, primary, alternate, out) \
	do { \
		if (ResolveFieldEither(types, _countof(types), primary, alternate, out) != SYMBOL_ERR_SUCCESS) { \
			LOG(1, "DynamicOffsets: missing %s/%s (tried %s)\n", primary, alternate, types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
	} while (0)

#define REQUIRE_SIZE(types, out) \
	do { \
		ULONG64 _sz = 0; \
		if (sym_parser.GetTypeSizeAny(types, _countof(types), _sz) != SYMBOL_ERR_SUCCESS || !_sz || _sz > 0x2000) { \
			LOG(1, "DynamicOffsets: bad size for %s\n", types[0]); \
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED; \
		} \
		(out) = static_cast<DWORD>(_sz); \
	} while (0)

	// TEB: SameTebFlags (worker check), LastErrorValue (stub gs:[] disp),
	// ProcessEnvironmentBlock (kept for completeness; version reads use API).
	REQUIRE_FIELD(kTeb, "SameTebFlags", tmp.TebSameTebFlags);
	REQUIRE_FIELD(kTeb, "LastErrorValue", tmp.TebLastErrorValue);
	REQUIRE_FIELD(kTeb, "ProcessEnvironmentBlock", tmp.TebProcessEnvironmentBlock);

	// PEB: version + loader pointers.
	REQUIRE_FIELD(kPeb, "OSMajorVersion", tmp.PebOsMajorVersion);
	REQUIRE_FIELD(kPeb, "OSMinorVersion", tmp.PebOsMinorVersion);
	REQUIRE_FIELD(kPeb, "OSBuildNumber", tmp.PebOsBuildNumber);
	REQUIRE_FIELD(kPeb, "Ldr", tmp.PebLdr);
	REQUIRE_FIELD(kPeb, "ProcessHeap", tmp.PebProcessHeap);
	REQUIRE_FIELD(kPeb, "LoaderLock", tmp.PebLoaderLock);
	REQUIRE_SIZE(kPeb, tmp.PebSize);

	// KUSER_SHARED_DATA.Cookie field (base 0x7FFE0000 is fixed mapping).
	REQUIRE_FIELD(kKuser, "Cookie", tmp.KuserCookie);

	// LDR entry + DDAG node.
	REQUIRE_FIELD(kLdrEntry, "DllBase", tmp.LdrEntryDllBase);
	REQUIRE_FIELD(kLdrEntry, "SizeOfImage", tmp.LdrEntrySizeOfImage);
	REQUIRE_FIELD(kLdrEntry, "FullDllName", tmp.LdrEntryFullDllName);
	REQUIRE_FIELD(kLdrEntry, "DdagNode", tmp.LdrEntryDdagNode);
	REQUIRE_SIZE(kLdrEntry, tmp.LdrEntrySize);
	REQUIRE_FIELD(kDdag, "State", tmp.LdrDdagNodeState);
	REQUIRE_SIZE(kDdag, tmp.LdrDdagNodeSize);

	// Inverted tables. Field names differ by build (Count/CurrentSize,
	// Entries/TableEntry, ImageSize/SizeOfImage,
	// ExceptionDirectory/FunctionTable, ExceptionDirectorySize/SizeOfTable);
	// the offsets are identical.
	REQUIRE_FIELD_ALT(kInvTable, "Count", "CurrentSize", tmp.InvertedTableCount);
	REQUIRE_FIELD_ALT(kInvTable, "Entries", "TableEntry", tmp.InvertedTableEntries);
	REQUIRE_FIELD(kInvEntry, "ImageBase", tmp.InvertedEntryImageBase);
	REQUIRE_FIELD_ALT(kInvEntry, "ImageSize", "SizeOfImage", tmp.InvertedEntryImageSize);
	REQUIRE_FIELD_ALT(kInvEntry, "ExceptionDirectory", "FunctionTable", tmp.InvertedEntryExceptionDirectory);
	REQUIRE_FIELD_ALT(kInvEntry, "ExceptionDirectorySize", "SizeOfTable", tmp.InvertedEntryExceptionDirectorySize);
	REQUIRE_SIZE(kInvEntry, tmp.InvertedEntrySize);

#undef REQUIRE_FIELD
#undef REQUIRE_FIELD_ALT
#undef REQUIRE_SIZE

	// TLS ModuleEntry: PDB-first, SDK-math fallback (not fail-closed: the type
	// name varies across PDB generations while the layout is LIST_ENTRY(16) +
	// IMAGE_TLS_DIRECTORY(40) + ModuleEntry, all SDK-stable).
	{
		DWORD off = 0;
		if (sym_parser.GetFieldOffsetAny(kTls, _countof(kTls), "ModuleEntry", off) == SYMBOL_ERR_SUCCESS && off && off < 0x200)
		{
			tmp.TlsEntryModuleEntry = off;
		}
		else
		{
			tmp.TlsEntryModuleEntry = static_cast<DWORD>(sizeof(LIST_ENTRY) + sizeof(IMAGE_TLS_DIRECTORY));
			LOG(1, "DynamicOffsets: TLS_ENTRY.ModuleEntry via SDK math 0x%X (PDB type absent)\n", tmp.TlsEntryModuleEntry);
		}
		ULONG64 tls_sz = 0;
		if (sym_parser.GetTypeSizeAny(kTls, _countof(kTls), tls_sz) == SYMBOL_ERR_SUCCESS && tls_sz && tls_sz < 0x400)
		{
			tmp.TlsEntrySize = static_cast<DWORD>(tls_sz);
		}
		else
		{
			tmp.TlsEntrySize = static_cast<DWORD>(sizeof(LIST_ENTRY) + sizeof(IMAGE_TLS_DIRECTORY) + sizeof(PVOID) + sizeof(SIZE_T));
			LOG(1, "DynamicOffsets: TLS_ENTRY size via SDK math %lu\n", tmp.TlsEntrySize);
		}
	}

	// LDRP_PATH_SEARCH_CONTEXT size + OriginalFullDllName offset: PDB-first,
	// static fallback (over-allocate is safe; under-allocate would corrupt).
	{
		// One definition shared by both fallbacks below. Layout is the
		// reverse-engineered context: it is only ever sized/offset, never
		// dereferenced.
		struct FALLBACK_CTX { wchar_t * a; void * b[3]; wchar_t * c; void * d[7]; ULONG64 e[4]; };

		ULONG64 ctx_sz = 0;
		if (sym_parser.GetTypeSizeAny(kPathCtx, _countof(kPathCtx), ctx_sz) == SYMBOL_ERR_SUCCESS && ctx_sz && ctx_sz < 0x1000)
		{
			tmp.LdrpPathSearchContextSize = static_cast<DWORD>(ctx_sz);
		}
		else
		{
			// Fallback keeps the reverse-engineered size; it is only a heap
			// allocation length, never an in-target field offset.
			tmp.LdrpPathSearchContextSize = static_cast<DWORD>(sizeof(FALLBACK_CTX));
			LOG(1, "DynamicOffsets: PATH_SEARCH_CONTEXT size via fallback %lu\n", tmp.LdrpPathSearchContextSize);
		}
		DWORD ctx_off = 0;
		if (sym_parser.GetFieldOffsetAny(kPathCtx, _countof(kPathCtx), "OriginalFullDllName", ctx_off) == SYMBOL_ERR_SUCCESS && ctx_off < 0x400)
		{
			tmp.LdrpPathSearchOriginalFullDllName = ctx_off;
		}
		else
		{
			tmp.LdrpPathSearchOriginalFullDllName = static_cast<DWORD>(offsetof(FALLBACK_CTX, c));
			LOG(1, "DynamicOffsets: PATH_SEARCH_CONTEXT.OriginalFullDllName via fallback 0x%X\n", tmp.LdrpPathSearchOriginalFullDllName);
		}
	}

	// Wait-stub return offset: disassemble NtDelayExecution in our own ntdll.
	// Per-function offsets are resolved by ProcessInformation at construction;
	// this global copy is the consensus value for logging/remote use.
	{
		auto ntdll_name = XOR_STR_W(L"ntdll.dll");
		HMODULE hNtdll = GetModuleHandleW(ntdll_name.get());
		if (!hNtdll)
		{
			LOG(1, "DynamicOffsets: no ntdll for wait disassembly\n");
			return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
		}
		auto dly = XOR_STR_A("NtDelayExecution");
		auto sng = XOR_STR_A("NtWaitForSingleObject");
		auto mul = XOR_STR_A("NtWaitForMultipleObjects");
		auto sig = XOR_STR_A("NtSignalAndWaitForSingleObject");
		void * fns[4] = {
			ReCa<void *>(GetProcAddress(hNtdll, dly.get())),
			ReCa<void *>(GetProcAddress(hNtdll, sng.get())),
			ReCa<void *>(GetProcAddress(hNtdll, mul.get())),
			ReCa<void *>(GetProcAddress(hNtdll, sig.get()))
		};
		DWORD first = 0;
		for (int i = 0; i < 4; ++i)
		{
			if (!fns[i])
			{
				LOG(1, "DynamicOffsets: missing wait export %d\n", i);
				return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
			}
			DWORD off = 0;
			if (DisassembleWaitReturnOffset(fns[i], off) != SYMBOL_ERR_SUCCESS)
			{
				return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
			}
			if (i == 0)
			{
				first = off;
			}
			else if (off != first)
			{
				LOG(1, "DynamicOffsets: wait stub drift fn[%d]=0x%X vs 0x%X\n", i, off, first);
				return SYMBOL_ERR_SYMBOL_SEARCH_FAILED;
			}
		}
		tmp.NtWaitReturnOffset = first;
		LOG(1, "DynamicOffsets: NtWaitReturnOffset=0x%X (disassembled, consensus 4 fns)\n", first);
	}

	// Stable ABI + enums: PDB first, documented fallback (not drift-prone).
	tmp.MsgWaitFlagsStackOffset = static_cast<DWORD>(sizeof(void *) + 0x20); // 0x28 on x64
	tmp.SameTebFlagsLoaderWorkerMask = 0x2000;
	{
		DWORD v = 0;
		if (sym_parser.GetEnumValueAny(kThreadState, _countof(kThreadState), "Running", v) == SYMBOL_ERR_SUCCESS)
		{
			tmp.ThreadStateRunning = v;
		}
		else
		{
			tmp.ThreadStateRunning = 2;
			LOG(2, "DynamicOffsets: Running via stable fallback 2\n");
		}
		if (sym_parser.GetEnumValueAny(kThreadState, _countof(kThreadState), "Waiting", v) == SYMBOL_ERR_SUCCESS)
		{
			tmp.ThreadStateWaiting = v;
		}
		else
		{
			tmp.ThreadStateWaiting = 5;
			LOG(2, "DynamicOffsets: Waiting via stable fallback 5\n");
		}
		if (sym_parser.GetEnumValueAny(kWaitReason, _countof(kWaitReason), "WrQueue", v) == SYMBOL_ERR_SUCCESS)
		{
			tmp.WaitReasonWrQueue = v;
		}
		else
		{
			tmp.WaitReasonWrQueue = 0x0F;
			LOG(2, "DynamicOffsets: WrQueue via stable fallback 0x0F\n");
		}
	}

	tmp.Ready = 1;
	g_DynamicOffsets = tmp;
	LOG(1, "DynamicOffsets ready: TEB{Flags=0x%X LastErr=0x%X Peb=0x%X} PEB{Build=0x%X Ldr=0x%X} KUSER{cookie=0x%X} LDR{DllBase=0x%X size=%lu} INV{count=0x%X entries=0x%X}\n",
		tmp.TebSameTebFlags, tmp.TebLastErrorValue, tmp.TebProcessEnvironmentBlock,
		tmp.PebOsBuildNumber, tmp.PebLdr, tmp.KuserCookie, tmp.LdrEntryDllBase, tmp.LdrEntrySize,
		tmp.InvertedTableCount, tmp.InvertedTableEntries);

	return SYMBOL_ERR_SUCCESS;
}

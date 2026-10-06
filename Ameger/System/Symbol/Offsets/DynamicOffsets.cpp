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
	if (g_DynamicOffsetsReady.load(std::memory_order_acquire))
	{
		return SYMBOL_ERR_SUCCESS;
	}

	DYNAMIC_NT_OFFSETS tmp{};

	// Every PDB type/field/enum name this resolver probes is held as
	// compile-time ciphertext and decrypted into stack buffers here; the
	// pointer arrays below only reference those buffers, which outlive every
	// read in this function. Nothing below is a plaintext .rdata literal.
	auto t_teb_a = XOR_STR_A("TEB");
	auto t_teb_b = XOR_STR_A("_TEB");
	auto t_peb_a = XOR_STR_A("PEB");
	auto t_peb_b = XOR_STR_A("_PEB");
	auto t_kuser_a = XOR_STR_A("_KUSER_SHARED_DATA");
	auto t_kuser_b = XOR_STR_A("KUSER_SHARED_DATA");
	auto t_ldr_a = XOR_STR_A("_LDR_DATA_TABLE_ENTRY");
	auto t_ldr_b = XOR_STR_A("LDR_DATA_TABLE_ENTRY");
	auto t_ddag_a = XOR_STR_A("_LDR_DDAG_NODE");
	auto t_ddag_b = XOR_STR_A("LDR_DDAG_NODE");
	auto t_invt_a = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE");
	auto t_invt_b = XOR_STR_A("RTL_INVERTED_FUNCTION_TABLE");
	auto t_invt_c = XOR_STR_A("_INVERTED_FUNCTION_TABLE_USER_MODE");
	auto t_invt_d = XOR_STR_A("INVERTED_FUNCTION_TABLE_USER_MODE");
	auto t_inve_a = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE_ENTRY");
	auto t_inve_b = XOR_STR_A("RTL_INVERTED_FUNCTION_TABLE_ENTRY");
	auto t_inve_c = XOR_STR_A("_INVERTED_FUNCTION_TABLE_ENTRY");
	auto t_inve_d = XOR_STR_A("INVERTED_FUNCTION_TABLE_ENTRY");
	auto t_tls_a = XOR_STR_A("_TLS_ENTRY");
	auto t_tls_b = XOR_STR_A("TLS_ENTRY");
	auto t_tls_c = XOR_STR_A("_LDRP_TLS_ENTRY");
	auto t_tls_d = XOR_STR_A("LDRP_TLS_ENTRY");
	auto t_path_a = XOR_STR_A("_LDRP_PATH_SEARCH_CONTEXT");
	auto t_path_b = XOR_STR_A("LDRP_PATH_SEARCH_CONTEXT");
	auto t_kstate_a = XOR_STR_A("_KTHREAD_STATE");
	auto t_kstate_b = XOR_STR_A("KTHREAD_STATE");
	auto t_kwait_a = XOR_STR_A("_KWAIT_REASON");
	auto t_kwait_b = XOR_STR_A("KWAIT_REASON");

	auto f_same_teb_flags = XOR_STR_A("SameTebFlags");
	auto f_last_error = XOR_STR_A("LastErrorValue");
	auto f_peb = XOR_STR_A("ProcessEnvironmentBlock");
	auto f_os_major = XOR_STR_A("OSMajorVersion");
	auto f_os_minor = XOR_STR_A("OSMinorVersion");
	auto f_os_build = XOR_STR_A("OSBuildNumber");
	auto f_ldr = XOR_STR_A("Ldr");
	auto f_process_heap = XOR_STR_A("ProcessHeap");
	auto f_loader_lock = XOR_STR_A("LoaderLock");
	auto f_cookie = XOR_STR_A("Cookie");
	auto f_dll_base = XOR_STR_A("DllBase");
	auto f_size_of_image = XOR_STR_A("SizeOfImage");
	auto f_full_dll_name = XOR_STR_A("FullDllName");
	auto f_ddag_node = XOR_STR_A("DdagNode");
	auto f_state = XOR_STR_A("State");
	auto f_count = XOR_STR_A("Count");
	auto f_current_size = XOR_STR_A("CurrentSize");
	auto f_entries = XOR_STR_A("Entries");
	auto f_table_entry = XOR_STR_A("TableEntry");
	auto f_image_base = XOR_STR_A("ImageBase");
	auto f_image_size = XOR_STR_A("ImageSize");
	auto f_exception_dir = XOR_STR_A("ExceptionDirectory");
	auto f_function_table = XOR_STR_A("FunctionTable");
	auto f_exception_dir_size = XOR_STR_A("ExceptionDirectorySize");
	auto f_size_of_table = XOR_STR_A("SizeOfTable");
	auto f_module_entry = XOR_STR_A("ModuleEntry");
	auto f_orig_full_dll = XOR_STR_A("OriginalFullDllName");
	auto f_running = XOR_STR_A("Running");
	auto f_waiting = XOR_STR_A("Waiting");
	auto f_wr_queue = XOR_STR_A("WrQueue");

	const char * kTeb[] = { t_teb_a.get(), t_teb_b.get() };
	const char * kPeb[] = { t_peb_a.get(), t_peb_b.get() };
	const char * kKuser[] = { t_kuser_a.get(), t_kuser_b.get() };
	const char * kLdrEntry[] = { t_ldr_a.get(), t_ldr_b.get() };
	const char * kDdag[] = { t_ddag_a.get(), t_ddag_b.get() };
	// Inverted function table. 26xxx renamed the types and their fields while
	// keeping the exact same on-disk layout (see NTDefinitions.h): the table
	// became _INVERTED_FUNCTION_TABLE_USER_MODE {CurrentSize,MaximumSize,
	// Epoch,Overflow,TableEntry} and the entry became
	// _INVERTED_FUNCTION_TABLE_ENTRY {union{FunctionTable,DynamicTable},
	// ImageBase,SizeOfImage,SizeOfTable}. Both spellings are attempted below;
	// the layout is still required to be present, so this stays fail-closed.
	const char * kInvTable[] = { t_invt_a.get(), t_invt_b.get(), t_invt_c.get(), t_invt_d.get() };
	const char * kInvEntry[] = { t_inve_a.get(), t_inve_b.get(), t_inve_c.get(), t_inve_d.get() };
	const char * kTls[] = { t_tls_a.get(), t_tls_b.get(), t_tls_c.get(), t_tls_d.get() };
	const char * kPathCtx[] = { t_path_a.get(), t_path_b.get() };
	const char * kThreadState[] = { t_kstate_a.get(), t_kstate_b.get() };
	const char * kWaitReason[] = { t_kwait_a.get(), t_kwait_b.get() };

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
	REQUIRE_FIELD(kTeb, f_same_teb_flags.get(), tmp.TebSameTebFlags);
	REQUIRE_FIELD(kTeb, f_last_error.get(), tmp.TebLastErrorValue);
	REQUIRE_FIELD(kTeb, f_peb.get(), tmp.TebProcessEnvironmentBlock);

	// PEB: version + loader pointers.
	REQUIRE_FIELD(kPeb, f_os_major.get(), tmp.PebOsMajorVersion);
	REQUIRE_FIELD(kPeb, f_os_minor.get(), tmp.PebOsMinorVersion);
	REQUIRE_FIELD(kPeb, f_os_build.get(), tmp.PebOsBuildNumber);
	REQUIRE_FIELD(kPeb, f_ldr.get(), tmp.PebLdr);
	REQUIRE_FIELD(kPeb, f_process_heap.get(), tmp.PebProcessHeap);
	REQUIRE_FIELD(kPeb, f_loader_lock.get(), tmp.PebLoaderLock);
	REQUIRE_SIZE(kPeb, tmp.PebSize);

	// KUSER_SHARED_DATA.Cookie field (base 0x7FFE0000 is fixed mapping).
	REQUIRE_FIELD(kKuser, f_cookie.get(), tmp.KuserCookie);

	// LDR entry + DDAG node.
	REQUIRE_FIELD(kLdrEntry, f_dll_base.get(), tmp.LdrEntryDllBase);
	REQUIRE_FIELD(kLdrEntry, f_size_of_image.get(), tmp.LdrEntrySizeOfImage);
	REQUIRE_FIELD(kLdrEntry, f_full_dll_name.get(), tmp.LdrEntryFullDllName);
	REQUIRE_FIELD(kLdrEntry, f_ddag_node.get(), tmp.LdrEntryDdagNode);
	REQUIRE_SIZE(kLdrEntry, tmp.LdrEntrySize);
	REQUIRE_FIELD(kDdag, f_state.get(), tmp.LdrDdagNodeState);
	REQUIRE_SIZE(kDdag, tmp.LdrDdagNodeSize);

	// Inverted tables. Field names differ by build (Count/CurrentSize,
	// Entries/TableEntry, ImageSize/SizeOfImage,
	// ExceptionDirectory/FunctionTable, ExceptionDirectorySize/SizeOfTable);
	// the offsets are identical.
	REQUIRE_FIELD_ALT(kInvTable, f_count.get(), f_current_size.get(), tmp.InvertedTableCount);
	REQUIRE_FIELD_ALT(kInvTable, f_entries.get(), f_table_entry.get(), tmp.InvertedTableEntries);
	REQUIRE_FIELD(kInvEntry, f_image_base.get(), tmp.InvertedEntryImageBase);
	REQUIRE_FIELD_ALT(kInvEntry, f_image_size.get(), f_size_of_image.get(), tmp.InvertedEntryImageSize);
	REQUIRE_FIELD_ALT(kInvEntry, f_exception_dir.get(), f_function_table.get(), tmp.InvertedEntryExceptionDirectory);
	REQUIRE_FIELD_ALT(kInvEntry, f_exception_dir_size.get(), f_size_of_table.get(), tmp.InvertedEntryExceptionDirectorySize);
	REQUIRE_SIZE(kInvEntry, tmp.InvertedEntrySize);

#undef REQUIRE_FIELD
#undef REQUIRE_FIELD_ALT
#undef REQUIRE_SIZE

	// TLS ModuleEntry: PDB-first, SDK-math fallback (not fail-closed: the type
	// name varies across PDB generations while the layout is LIST_ENTRY(16) +
	// IMAGE_TLS_DIRECTORY(40) + ModuleEntry, all SDK-stable).
	{
		DWORD off = 0;
		if (sym_parser.GetFieldOffsetAny(kTls, _countof(kTls), f_module_entry.get(), off) == SYMBOL_ERR_SUCCESS && off && off < 0x200)
		{
			tmp.TlsEntryModuleEntry = off;
		}
		else
		{
			tmp.TlsEntryModuleEntry = static_cast<DWORD>(sizeof(LIST_ENTRY) + sizeof(IMAGE_TLS_DIRECTORY));
			LOG(1, "DynamicOffsets: TLS slot via SDK math 0x%X (PDB type absent)\n", tmp.TlsEntryModuleEntry);
		}
		ULONG64 tls_sz = 0;
		if (sym_parser.GetTypeSizeAny(kTls, _countof(kTls), tls_sz) == SYMBOL_ERR_SUCCESS && tls_sz && tls_sz < 0x400)
		{
			tmp.TlsEntrySize = static_cast<DWORD>(tls_sz);
		}
		else
		{
			tmp.TlsEntrySize = static_cast<DWORD>(sizeof(LIST_ENTRY) + sizeof(IMAGE_TLS_DIRECTORY) + sizeof(PVOID) + sizeof(SIZE_T));
			LOG(1, "DynamicOffsets: TLS size via SDK math %lu\n", tmp.TlsEntrySize);
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
			LOG(1, "DynamicOffsets: path context size via fallback %lu\n", tmp.LdrpPathSearchContextSize);
		}
		DWORD ctx_off = 0;
		if (sym_parser.GetFieldOffsetAny(kPathCtx, _countof(kPathCtx), f_orig_full_dll.get(), ctx_off) == SYMBOL_ERR_SUCCESS && ctx_off < 0x400)
		{
			tmp.LdrpPathSearchOriginalFullDllName = ctx_off;
		}
		else
		{
			tmp.LdrpPathSearchOriginalFullDllName = static_cast<DWORD>(offsetof(FALLBACK_CTX, c));
			LOG(1, "DynamicOffsets: path context name via fallback 0x%X\n", tmp.LdrpPathSearchOriginalFullDllName);
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
			LOG(1, "DynamicOffsets: no OS module for wait disassembly\n");
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
	}

	// Stable ABI + enums: PDB first, documented fallback (not drift-prone).
	tmp.MsgWaitFlagsStackOffset = static_cast<DWORD>(sizeof(void *) + 0x20); // 0x28 on x64
	tmp.SameTebFlagsLoaderWorkerMask = 0x2000;
	{
		DWORD v = 0;
		if (sym_parser.GetEnumValueAny(kThreadState, _countof(kThreadState), f_running.get(), v) == SYMBOL_ERR_SUCCESS)
		{
			tmp.ThreadStateRunning = v;
		}
		else
		{
			tmp.ThreadStateRunning = 2;
			LOG(2, "DynamicOffsets: Running via stable fallback 2\n");
		}
		if (sym_parser.GetEnumValueAny(kThreadState, _countof(kThreadState), f_waiting.get(), v) == SYMBOL_ERR_SUCCESS)
		{
			tmp.ThreadStateWaiting = v;
		}
		else
		{
			tmp.ThreadStateWaiting = 5;
			LOG(2, "DynamicOffsets: Waiting via stable fallback 5\n");
		}
		if (sym_parser.GetEnumValueAny(kWaitReason, _countof(kWaitReason), f_wr_queue.get(), v) == SYMBOL_ERR_SUCCESS)
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
	// Publish only after every field is written: release-store the flag so a
	// consumer's acquire-load of g_DynamicOffsetsReady observes the full
	// struct. Ready is also set in tmp for the MANUAL_MAPPING_DATA copy, but
	// this atomic store is the synchronization primitive.
	g_DynamicOffsetsReady.store(1, std::memory_order_release);
	LOG(1, "DynamicOffsets ready: t0=0x%X t1=0x%X t2=0x%X p0=0x%X p1=0x%X k0=0x%X l0=0x%X sz=%lu i0=0x%X i1=0x%X\n",
		tmp.TebSameTebFlags, tmp.TebLastErrorValue, tmp.TebProcessEnvironmentBlock,
		tmp.PebOsBuildNumber, tmp.PebLdr, tmp.KuserCookie, tmp.LdrEntryDllBase, tmp.LdrEntrySize,
		tmp.InvertedTableCount, tmp.InvertedTableEntries);

	return SYMBOL_ERR_SUCCESS;
}

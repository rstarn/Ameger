#pragma once

#include <Windows.h>

#include <algorithm>

#include "Core/Foundation/Error.h"

namespace PE_IMAGE
{
	constexpr DWORD MAX_IMAGE_SIZE = 0x40000000;
	constexpr WORD MAX_SECTION_COUNT = 96;

	struct OPTIONS
	{
		bool RequireDll = false;
		bool RequireExports = false;
		bool RequireRelocations = false;
		bool ResolveImports = false;
		bool ResolveDelayImports = false;
		bool EnableExceptions = false;
		bool InitializeSecurityCookie = false;
		bool ExecuteTls = false;
	};

	struct VIEW
	{
		const BYTE * Data = nullptr;
		size_t Size = 0;
		const IMAGE_NT_HEADERS64 * NtHeaders = nullptr;
		const IMAGE_SECTION_HEADER * Sections = nullptr;
	};

	struct MAPPING
	{
		const BYTE * Data = nullptr;
		size_t Available = 0;
	};

	__forceinline bool RangeWithin(size_t offset, size_t count, size_t total)
	{
		return offset <= total && count <= total - offset;
	}

	__forceinline bool IsPowerOfTwo(DWORD value)
	{
		return value != 0 && (value & (value - 1)) == 0;
	}

	__forceinline bool IsAligned(DWORD value, DWORD alignment)
	{
		return IsPowerOfTwo(alignment) && (value & (alignment - 1)) == 0;
	}

	__forceinline const IMAGE_SECTION_HEADER * FindSection(const VIEW & view, DWORD rva)
	{
		const IMAGE_FILE_HEADER & file_header = view.NtHeaders->FileHeader;

		for (WORD index = 0; index < file_header.NumberOfSections; ++index)
		{
			const IMAGE_SECTION_HEADER & section = view.Sections[index];
			const DWORD span = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
			if (rva >= section.VirtualAddress && rva - section.VirtualAddress < span)
			{
				return &section;
			}
		}

		return nullptr;
	}

	__forceinline MAPPING MapRva(const VIEW & view, DWORD rva)
	{
		if (rva < view.NtHeaders->OptionalHeader.SizeOfHeaders)
		{
			if (!RangeWithin(rva, 1, view.Size))
			{
				return {};
			}

			return { view.Data + rva, view.NtHeaders->OptionalHeader.SizeOfHeaders - rva };
		}

		const IMAGE_SECTION_HEADER * section = FindSection(view, rva);
		if (!section || !section->SizeOfRawData)
		{
			return {};
		}

		const DWORD raw_offset = rva - section->VirtualAddress;
		if (raw_offset >= section->SizeOfRawData)
		{
			return {};
		}

		return { view.Data + section->PointerToRawData + raw_offset, section->SizeOfRawData - raw_offset };
	}

	__forceinline bool IsZeroTerminated(const BYTE * data, size_t available)
	{
		for (size_t index = 0; index < available; ++index)
		{
			if (data[index] == 0)
			{
				return true;
			}
		}

		return false;
	}

	__forceinline bool ValidateThunkTable(const VIEW & view, DWORD rva)
	{
		const MAPPING mapping = MapRva(view, rva);
		if (!mapping.Data || mapping.Available < sizeof(IMAGE_THUNK_DATA64))
		{
			return false;
		}

		const size_t maximum_entries = mapping.Available / sizeof(IMAGE_THUNK_DATA64);
		for (size_t index = 0; index < maximum_entries; ++index)
		{
			const IMAGE_THUNK_DATA64 & thunk = *reinterpret_cast<const IMAGE_THUNK_DATA64 *>(mapping.Data + index * sizeof(IMAGE_THUNK_DATA64));
			if (!thunk.u1.AddressOfData)
			{
				return true;
			}

			if (!IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal))
			{
				const MAPPING name_mapping = MapRva(view, static_cast<DWORD>(thunk.u1.AddressOfData));
				if (!name_mapping.Data || name_mapping.Available < sizeof(WORD) || !IsZeroTerminated(name_mapping.Data + sizeof(WORD), name_mapping.Available - sizeof(WORD)))
				{
					return false;
				}
			}
		}

		return false;
	}

	__forceinline bool ValidateImports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!directory.Size)
		{
			return true;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			return false;
		}

		for (size_t offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= directory.Size; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
		{
			const IMAGE_IMPORT_DESCRIPTOR & descriptor = *reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(mapping.Data + offset);
			if (!descriptor.Name)
			{
				return true;
			}

			if (!MapRva(view, descriptor.Name).Data)
			{
				return false;
			}

			const DWORD thunk_rva = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
			if (!thunk_rva || !ValidateThunkTable(view, thunk_rva))
			{
				return false;
			}

			// FirstThunk is the IAT the resolver writes resolved pointers into.
			// A descriptor with a valid OriginalFirstThunk but FirstThunk == 0
			// passes the ILT check above, yet the loader would write at
			// pImageBase + 0 - the DOS/NT headers. Require a non-zero, in-image
			// IAT as the PE spec mandates. OriginalFirstThunk == 0 descriptors
			// stay valid: FirstThunk is then the thunk_rva checked above, and a
			// bound IAT is never walked here as a name table.
			if (!descriptor.FirstThunk || !RangeWithin(descriptor.FirstThunk, sizeof(IMAGE_THUNK_DATA64), view.NtHeaders->OptionalHeader.SizeOfImage))
			{
				return false;
			}
		}

		return false;
	}

	__forceinline bool ValidateDelayImports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
		if (!directory.Size)
		{
			return true;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))
		{
			return false;
		}

		for (size_t offset = 0; offset + sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) <= directory.Size; offset += sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))
		{
			const IMAGE_DELAYLOAD_DESCRIPTOR & descriptor = *reinterpret_cast<const IMAGE_DELAYLOAD_DESCRIPTOR *>(mapping.Data + offset);
			if (!descriptor.DllNameRVA)
			{
				return true;
			}

			// ImportAddressTableRVA is the delay IAT the resolver writes into,
			// so it must be non-zero and in-image for the same reason as the
			// classic FirstThunk above. ImportNameTableRVA is the read-only
			// name table walked by ValidateThunkTable.
			if (!MapRva(view, descriptor.DllNameRVA).Data ||
				!descriptor.ImportAddressTableRVA ||
				!RangeWithin(descriptor.ImportAddressTableRVA, sizeof(IMAGE_THUNK_DATA64), view.NtHeaders->OptionalHeader.SizeOfImage) ||
				!descriptor.ImportNameTableRVA ||
				!ValidateThunkTable(view, descriptor.ImportNameTableRVA))
			{
				return false;
			}
		}

		return false;
	}

	__forceinline bool ValidateExports(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!directory.Size)
		{
			return false;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
		{
			return false;
		}

		const IMAGE_EXPORT_DIRECTORY & exports = *reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(mapping.Data);
		if (!exports.NumberOfFunctions || !exports.NumberOfNames || !exports.AddressOfFunctions || !exports.AddressOfNames || !exports.AddressOfNameOrdinals)
		{
			return false;
		}

		const MAPPING functions = MapRva(view, exports.AddressOfFunctions);
		const MAPPING names = MapRva(view, exports.AddressOfNames);
		const MAPPING ordinals = MapRva(view, exports.AddressOfNameOrdinals);
		const size_t function_bytes = static_cast<size_t>(exports.NumberOfFunctions) * sizeof(ULONG);
		const size_t name_bytes = static_cast<size_t>(exports.NumberOfNames) * sizeof(ULONG);
		const size_t ordinal_bytes = static_cast<size_t>(exports.NumberOfNames) * sizeof(USHORT);
		if (!functions.Data || !names.Data || !ordinals.Data || function_bytes > functions.Available || name_bytes > names.Available || ordinal_bytes > ordinals.Available)
		{
			return false;
		}

		for (DWORD index = 0; index < exports.NumberOfNames; ++index)
		{
			const DWORD name_rva = *reinterpret_cast<const DWORD *>(names.Data + index * sizeof(DWORD));
			const USHORT ordinal = *reinterpret_cast<const USHORT *>(ordinals.Data + index * sizeof(USHORT));
			if (!name_rva || ordinal >= exports.NumberOfFunctions || !MapRva(view, name_rva).Data)
			{
				return false;
			}
		}

		return true;
	}

	__forceinline bool ValidateRelocations(const VIEW & view)
	{
		const IMAGE_DATA_DIRECTORY & directory = view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (!directory.Size)
		{
			return false;
		}

		const MAPPING mapping = MapRva(view, directory.VirtualAddress);
		if (!mapping.Data || mapping.Available < directory.Size)
		{
			return false;
		}

		size_t offset = 0;
		while (offset < directory.Size)
		{
			if (directory.Size - offset < sizeof(IMAGE_BASE_RELOCATION))
			{
				return false;
			}

			const IMAGE_BASE_RELOCATION & block = *reinterpret_cast<const IMAGE_BASE_RELOCATION *>(mapping.Data + offset);
			if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || block.SizeOfBlock > directory.Size - offset || (block.SizeOfBlock & 1))
			{
				return false;
			}

			const size_t entry_count = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			const WORD * entries = reinterpret_cast<const WORD *>(mapping.Data + offset + sizeof(IMAGE_BASE_RELOCATION));
			for (size_t index = 0; index < entry_count; ++index)
			{
				const WORD type = entries[index] >> 12;
				if (type == IMAGE_REL_BASED_ABSOLUTE)
				{
					continue;
				}
				if (type != IMAGE_REL_BASED_DIR64)
				{
					return false;
				}

				const DWORD patch_rva = block.VirtualAddress + static_cast<DWORD>(entries[index] & 0x0FFF);
				// Guard the subtraction: SizeOfImage < sizeof(ULONG_PTR) would
				// wrap to a huge bound and disable the check entirely.
				if (view.NtHeaders->OptionalHeader.SizeOfImage < sizeof(ULONG_PTR) ||
					patch_rva > view.NtHeaders->OptionalHeader.SizeOfImage - sizeof(ULONG_PTR))
				{
					return false;
				}
			}

			offset += block.SizeOfBlock;
		}

		return offset == directory.Size;
	}

	__forceinline DWORD Validate(const BYTE * data, size_t size, DWORD target_machine, const OPTIONS & options, VIEW & view)
	{
		if (!data || size < sizeof(IMAGE_DOS_HEADER))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_DOS_HEADER & dos_header = *reinterpret_cast<const IMAGE_DOS_HEADER *>(data);
		if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || dos_header.e_lfanew < sizeof(IMAGE_DOS_HEADER))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const size_t nt_offset = static_cast<size_t>(dos_header.e_lfanew);
		if (!RangeWithin(nt_offset, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64), size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_NT_HEADERS64 & nt_headers = *reinterpret_cast<const IMAGE_NT_HEADERS64 *>(data + nt_offset);
		if (nt_headers.Signature != IMAGE_NT_SIGNATURE || nt_headers.FileHeader.Machine != target_machine || nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (nt_headers.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) || !RangeWithin(nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), nt_headers.FileHeader.SizeOfOptionalHeader, size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const WORD section_count = nt_headers.FileHeader.NumberOfSections;
		if (!section_count || section_count > MAX_SECTION_COUNT)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const size_t section_table_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader;
		const size_t section_table_size = static_cast<size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER);
		const DWORD file_alignment = nt_headers.OptionalHeader.FileAlignment;
		const DWORD section_alignment = nt_headers.OptionalHeader.SectionAlignment;
		const DWORD size_of_headers = nt_headers.OptionalHeader.SizeOfHeaders;
		const DWORD size_of_image = nt_headers.OptionalHeader.SizeOfImage;

		if (nt_headers.OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
			!IsPowerOfTwo(file_alignment) || file_alignment < 0x200 || file_alignment > 0x10000 ||
			!IsPowerOfTwo(section_alignment) || section_alignment < file_alignment || section_alignment > 0x10000 ||
			!IsAligned(size_of_headers, file_alignment) || !IsAligned(size_of_image, section_alignment) ||
			!size_of_headers || size_of_headers > size || size_of_headers > size_of_image || size_of_headers > MAX_IMAGE_SIZE || size_of_image > MAX_IMAGE_SIZE ||
			!RangeWithin(nt_offset, section_table_offset - nt_offset + section_table_size, size_of_headers) ||
			!RangeWithin(section_table_offset, section_table_size, size))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (options.RequireDll && !(nt_headers.FileHeader.Characteristics & IMAGE_FILE_DLL))
		{
			return FILE_ERR_INVALID_FILE;
		}

		if (nt_headers.OptionalHeader.AddressOfEntryPoint >= size_of_image ||
			nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_SECTION_HEADER * sections = reinterpret_cast<const IMAGE_SECTION_HEADER *>(data + section_table_offset);
		view.Data = data;
		view.Size = size;
		view.NtHeaders = &nt_headers;
		view.Sections = sections;

		for (WORD index = 0; index < section_count; ++index)
		{
			const IMAGE_SECTION_HEADER & section = sections[index];
			const ULONGLONG section_span = (std::max)(static_cast<ULONGLONG>(section.Misc.VirtualSize), static_cast<ULONGLONG>(section.SizeOfRawData));
			const ULONGLONG section_end = static_cast<ULONGLONG>(section.VirtualAddress) + section_span;
			if (!section.VirtualAddress || !IsAligned(section.VirtualAddress, section_alignment) || section_end > size_of_image)
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}

			if (section.SizeOfRawData)
			{
				if (!IsAligned(section.PointerToRawData, file_alignment) || section.PointerToRawData < size_of_headers || !RangeWithin(section.PointerToRawData, section.SizeOfRawData, size))
				{
					return FILE_ERR_INVALID_PE_LAYOUT;
				}
			}
		}

		for (DWORD index = 0; index < nt_headers.OptionalHeader.NumberOfRvaAndSizes; ++index)
		{
			const IMAGE_DATA_DIRECTORY & directory = nt_headers.OptionalHeader.DataDirectory[index];
			if (!directory.Size)
			{
				continue;
			}

			if (index == IMAGE_DIRECTORY_ENTRY_SECURITY)
			{
				if (!RangeWithin(directory.VirtualAddress, directory.Size, size))
				{
					return FILE_ERR_INVALID_PE_LAYOUT;
				}
			}
			else if (!RangeWithin(directory.VirtualAddress, directory.Size, size_of_image))
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}
		}

		const IMAGE_DATA_DIRECTORY & load_config = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		if (load_config.Size && load_config.Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SecurityCookie) + sizeof(ULONG_PTR))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}
		const IMAGE_DATA_DIRECTORY & exceptions = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (exceptions.Size && exceptions.Size % sizeof(RUNTIME_FUNCTION))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}
		if (options.EnableExceptions && !exceptions.Size)
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		const IMAGE_DATA_DIRECTORY & tls = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (tls.Size)
		{
			const MAPPING tls_mapping = MapRva(view, tls.VirtualAddress);
			if (tls.Size < sizeof(IMAGE_TLS_DIRECTORY) || !tls_mapping.Data || tls_mapping.Available < sizeof(IMAGE_TLS_DIRECTORY))
			{
				return FILE_ERR_INVALID_PE_LAYOUT;
			}
		}

		if (options.RequireExports && !ValidateExports(view))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		if (options.RequireRelocations && !ValidateRelocations(view))
		{
			return FILE_ERR_RELOCATIONS_REQUIRED;
		}

		if ((options.ResolveImports && !ValidateImports(view)) || (options.ResolveDelayImports && !ValidateDelayImports(view)))
		{
			return FILE_ERR_INVALID_PE_LAYOUT;
		}

		return FILE_ERR_SUCCESS;
	}
}

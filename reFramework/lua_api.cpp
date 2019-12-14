#include "main.hpp"
#include <iterator>
#pragma warning(disable : 26444)

struct pe_handle
{
	std::optional<pe_base> get_image(std::string filename)
	{
		std::ifstream pe_file(filename, std::ios::in | std::ios::binary);
		if (!pe_file)
		{
			std::cerr << "Cannot open " << filename << endl;
			return std::nullopt;
		}

		try
		{
			pe_base pe_image(pe_factory::create_pe(pe_file));

			return std::optional<pe_base>(pe_image);
		}
		catch (const pe_exception & e)
		{
			std::cerr << "Error: " << e.what() << std::endl;
			return std::nullopt;
		}
		return std::nullopt;
	}

	std::optional<imported_functions_list> get_imports(pe_base &pe) const {
		return std::optional<imported_functions_list>(pe_bliss::get_imported_functions(pe));
	}

	std::uint32_t calculate_entropy(pe_base& pe) const {
		return pe_bliss::entropy_calculator::calculate_entropy(pe);
	}

	void rebuild_pe(pe_base& pe, std::string new_pe_fn, bool strip_dos, bool change_headers_size, bool save_bound_imports)
	{
		std::ofstream new_pe_file(new_pe_fn, std::ios::out | std::ios::binary | std::ios::trunc);
		if (!new_pe_file)
		{
			std::cout << "Cannot create " << new_pe_fn << endl;
			return;
		}
		pe_bliss::rebuild_pe(pe, new_pe_file, strip_dos, change_headers_size, save_bound_imports);
	}
};

void LuaAPI::Init()
{
	G::Lua.new_enum("pe_win",
		"image_directory_entry_import", pe_win::image_directory_entry_import,
		"image_directory_entry_tls", pe_win::image_directory_entry_tls,
		"image_directory_entry_basereloc", pe_win::image_directory_entry_basereloc,
		"image_directory_entry_export", pe_win::image_directory_entry_export,
		"image_directory_entry_exception", pe_win::image_directory_entry_exception,
		"image_directory_entry_iat", pe_win::image_directory_entry_iat,
		"image_directory_entry_architecture", pe_win::image_directory_entry_architecture,
		"image_directory_entry_bound_import", pe_win::image_directory_entry_bound_import,
		"image_directory_entry_debug", pe_win::image_directory_entry_debug,
		"image_directory_entry_com_descriptor", pe_win::image_directory_entry_com_descriptor,
		"image_directory_entry_security", pe_win::image_directory_entry_security,
		"image_directory_entry_resource", pe_win::image_directory_entry_resource,
		"image_directory_entry_globalptr", pe_win::image_directory_entry_globalptr
	);

	G::Lua.new_usertype<pe_bliss::pe_base>("pe_base",
		"get_pe_type", sol::readonly_property(sol::resolve<pe_bliss::pe_type() const>(&pe_bliss::pe_base::get_pe_type)),
		"get_magic", sol::readonly_property (&pe_bliss::pe_base::get_magic),
		"get_file_alignment", sol::readonly_property(&pe_bliss::pe_base::get_file_alignment),
		"get_section_alignment", sol::readonly_property(&pe_bliss::pe_base::get_section_alignment),
		"get_subsystem", sol::readonly_property(&pe_bliss::pe_base::get_subsystem),
		"get_image_base_32", sol::readonly_property(&pe_bliss::pe_base::get_image_base_32),
		"get_image_base_64", sol::readonly_property(&pe_bliss::pe_base::get_image_base_64),
		"get_checksum", sol::readonly_property(&pe_bliss::pe_base::get_checksum),
		"get_characteristics", sol::readonly_property(&pe_bliss::pe_base::get_characteristics),
		"get_ep", sol::readonly_property(&pe_bliss::pe_base::get_ep),
		"get_dll_characteristics", sol::readonly_property(&pe_bliss::pe_base::get_dll_characteristics),
		"get_base_of_code", sol::readonly_property(&pe_bliss::pe_base::get_base_of_code),
		"get_pe_header_start", sol::readonly_property(&pe_bliss::pe_base::get_pe_header_start),
		"get_size_of_image", sol::readonly_property(&pe_bliss::pe_base::get_size_of_image),
		"get_size_of_optional_header", sol::readonly_property(&pe_bliss::pe_base::get_size_of_optional_header),
		"has_imports", sol::readonly_property(&pe_bliss::pe_base::has_imports),
		"has_tls", sol::readonly_property(&pe_bliss::pe_base::has_tls),
		"has_imports", sol::readonly_property(&pe_bliss::pe_base::has_imports),
		"has_bound_import", sol::readonly_property(&pe_bliss::pe_base::has_bound_import),
		"has_config", sol::readonly_property(&pe_bliss::pe_base::has_config),
		"has_reloc", sol::readonly_property(&pe_bliss::pe_base::has_reloc),
		"has_security", sol::readonly_property(&pe_bliss::pe_base::has_security),
		"has_delay_import", sol::readonly_property(&pe_bliss::pe_base::has_delay_import),
		"has_exception_directory", sol::readonly_property(&pe_bliss::pe_base::has_exception_directory),
		"has_resources", sol::readonly_property(&pe_bliss::pe_base::has_resources),
		"has_exports", sol::readonly_property(&pe_bliss::pe_base::has_exports),
		"is_dotnet", sol::readonly_property(&pe_bliss::pe_base::is_dotnet),
		"is_console", sol::readonly_property(&pe_bliss::pe_base::is_console),
		"is_gui", sol::readonly_property(&pe_bliss::pe_base::is_gui),

		"add_section", & pe_bliss::pe_base::add_section,
		"strip_stub_overlay", &pe_bliss::pe_base::strip_stub_overlay,
		"strip_data_directories", &pe_bliss::pe_base::strip_data_directories,
		"realign_file", &pe_bliss::pe_base::realign_file,

		"get_image_sections", sol::readonly_property(sol::resolve<pe_bliss::section_list&()>(&pe_bliss::pe_base::get_image_sections)),
		"section_from_directory", sol::readonly_property(sol::resolve<pe_bliss::section & (std::uint32_t)>(&pe_bliss::pe_base::section_from_directory))

		);

	G::Lua.new_usertype<pe_bliss::section>("section",
		"get_name", sol::readonly_property(&pe_bliss::section::get_name),
		"get_characteristics", sol::readonly_property(&pe_bliss::section::get_characteristics),
		"get_aligned_raw_size", sol::readonly_property(&pe_bliss::section::get_aligned_raw_size),
		"get_aligned_virtual_size", sol::readonly_property(&pe_bliss::section::get_aligned_virtual_size),
		"get_pointer_to_raw_data", sol::readonly_property(&pe_bliss::section::get_pointer_to_raw_data),
		"get_raw_data", sol::resolve<std::string &()>(&pe_bliss::section::get_raw_data),
		"get_size_of_raw_data", sol::readonly_property(&pe_bliss::section::get_size_of_raw_data),
		"get_virtual_address", sol::readonly_property(&pe_bliss::section::get_virtual_address),
		"get_virtual_size", sol::readonly_property(&pe_bliss::section::get_virtual_size),
		"executable", sol::property(sol::resolve<pe_bliss::section &(bool)>(&pe_bliss::section::executable), sol::resolve<bool() const>(&pe_bliss::section::executable)),
		"writeable", sol::property(sol::resolve<pe_bliss::section &(bool)>(&pe_bliss::section::writeable), sol::resolve<bool() const>(&pe_bliss::section::writeable)),
		"readable", sol::property(sol::resolve<pe_bliss::section &(bool)>(&pe_bliss::section::readable), sol::resolve<bool() const>(&pe_bliss::section::readable)),
		"shared", sol::property(sol::resolve<pe_bliss::section &(bool)>(&pe_bliss::section::shared), sol::resolve<bool() const>(&pe_bliss::section::shared)),
		"discardable", sol::property(sol::resolve<pe_bliss::section &(bool)>(&pe_bliss::section::discardable), sol::resolve<bool() const>(&pe_bliss::section::discardable)),
		"empty", sol::readonly_property(&pe_bliss::section::empty),

		"set_characteristics", sol::writeonly_property(&pe_bliss::section::set_characteristics),
		"set_name", sol::writeonly_property(&pe_bliss::section::set_name),
		"set_pointer_to_raw_data", sol::writeonly_property(&pe_bliss::section::set_pointer_to_raw_data),
		"set_raw_data", sol::writeonly_property(&pe_bliss::section::set_raw_data),
		"set_size_of_raw_data", sol::writeonly_property(&pe_bliss::section::set_size_of_raw_data),
		"set_virtual_address", sol::writeonly_property(&pe_bliss::section::set_virtual_address),
		"set_virtual_size", sol::writeonly_property(&pe_bliss::section::set_virtual_size)
		);

	G::Lua.new_usertype<pe_bliss::relocation_entry>("relocation_entry",
		"get_item", sol::property(&pe_bliss::relocation_entry::get_item),
		"get_rva", sol::property(&pe_bliss::relocation_entry::get_rva),
		"get_type", sol::property(&pe_bliss::relocation_entry::get_type),

		"set_item", sol::writeonly_property(&pe_bliss::relocation_entry::set_item),
		"set_rva", sol::writeonly_property(&pe_bliss::relocation_entry::set_rva),
		"set_type", sol::writeonly_property(&pe_bliss::relocation_entry::set_type)
		);

	G::Lua.new_usertype<pe_bliss::relocation_table>("relocation_table",
		"get_relocations", sol::readonly_property(sol::resolve<pe_bliss::relocation_table::relocation_list &()>(&pe_bliss::relocation_table::get_relocations)),
		"add_relocation", sol::writeonly_property(&pe_bliss::relocation_table::add_relocation),
		"get_rva", sol::readonly_property(&pe_bliss::relocation_table::get_rva),
		"set_rva", sol::writeonly_property(&pe_bliss::relocation_table::set_rva)
		);
	
	G::Lua.new_usertype<pe_bliss::import_library>("import_library",
		"get_name", sol::readonly_property(&pe_bliss::import_library::get_name),
		"get_timestamp", sol::readonly_property(&pe_bliss::import_library::get_timestamp),
		"get_rva_to_iat", sol::readonly_property(&pe_bliss::import_library::get_rva_to_iat),
		"get_rva_to_original_iat", sol::readonly_property(&pe_bliss::import_library::get_rva_to_original_iat),
		"get_imported_functions", sol::readonly_property(&pe_bliss::import_library::get_imported_functions),
		
		"set_name", sol::writeonly_property(&pe_bliss::import_library::set_name),
		"set_rva_to_iat", sol::writeonly_property(&pe_bliss::import_library::set_rva_to_iat),
		"set_rva_to_original_iat", sol::writeonly_property(&pe_bliss::import_library::set_rva_to_original_iat),
		"set_timestamp", sol::writeonly_property(&pe_bliss::import_library::set_timestamp),

		"add_import", sol::writeonly_property(&pe_bliss::import_library::add_import)
		);
	
	G::Lua.new_usertype<pe_bliss::imported_function>("imported_function",
		"get_name", sol::readonly_property(&pe_bliss::imported_function::get_name),
		"get_iat_va", sol::readonly_property(&pe_bliss::imported_function::get_iat_va),
		"get_hint", sol::readonly_property(&pe_bliss::imported_function::get_hint),
		"get_ordinal", sol::readonly_property(&pe_bliss::imported_function::get_ordinal),
		"has_name", sol::readonly_property(&pe_bliss::imported_function::has_name),

		"set_hint", sol::writeonly_property(&imported_function::set_hint),
		"set_iat_va", sol::writeonly_property(&imported_function::set_iat_va),
		"set_name", sol::writeonly_property(&imported_function::set_name),
		"set_ordinal", sol::writeonly_property(&imported_function::set_ordinal)
		);

	G::Lua.new_usertype<pe_bliss::exported_function>("exported_function",
		"get_name", sol::readonly_property(&pe_bliss::exported_function::get_name),
		"get_forwarded_name", sol::readonly_property(&pe_bliss::exported_function::get_forwarded_name),
		"get_name_ordinal", sol::readonly_property(&pe_bliss::exported_function::get_name_ordinal),
		"get_ordinal", sol::readonly_property(&pe_bliss::exported_function::get_ordinal),
		"get_rva", sol::readonly_property(&pe_bliss::exported_function::get_rva),
		"has_name", sol::readonly_property(&pe_bliss::exported_function::has_name),
		"is_forwarded", sol::readonly_property(&pe_bliss::exported_function::is_forwarded),

		"set_forwarded_name", sol::writeonly_property(&pe_bliss::exported_function::set_forwarded_name),
		"set_name", sol::writeonly_property(&pe_bliss::exported_function::set_name),
		"set_name_ordinal", sol::writeonly_property(&pe_bliss::exported_function::set_name_ordinal),
		"set_ordinal", sol::writeonly_property(&pe_bliss::exported_function::set_ordinal),
		"set_rva", sol::writeonly_property(&pe_bliss::exported_function::set_rva)
		);

	G::Lua.new_usertype<pe_handle>("pe_handle",
		"get_image", &pe_handle::get_image,
		"get_imports", &pe_handle::get_imports,
		"rebuild_pe", &pe_handle::rebuild_pe,
		"calculate_entropy", &pe_handle::calculate_entropy,
		"rebuild_relocs", &pe_bliss::rebuild_relocations,
		"rebuild_imports", &pe_bliss::rebuild_imports
		);

	G::Lua.new_usertype<cs_x86_encoding>("cs_x86_encoding",
		"disp_offset", [](cs_x86_encoding& s) { return (uint32_t)s.disp_offset; },
		"disp_size", [](cs_x86_encoding& s) { return (uint32_t)s.disp_size; },
		"imm_offset", [](cs_x86_encoding& s) { return (uint32_t)s.imm_offset; },
		"imm_size", [](cs_x86_encoding& s) { return (uint32_t)s.imm_size; },
		"modrm_offset", [](cs_x86_encoding& s) { return (uint32_t)s.modrm_offset; }
	);

	G::Lua.new_usertype<cs_x86>("cs_x86",
		"prefix", [](cs_x86& s) { return std::ref(s.prefix); },
		"opcode", [](cs_x86& s) { return (uint32_t)s.opcode; },
		"op_count", [](cs_x86& s) { return (uint32_t)s.op_count; },
		"addr_size", [](cs_x86& s) { return (uint32_t)s.addr_size; },
		"eflags", [](cs_x86& s) { return (uint64_t)s.eflags; },
		"disp", [](cs_x86& s) { return (uint64_t)s.disp; },

		"encoding", [](cs_x86& s) { return s.encoding; }
	);

	G::Lua.new_usertype<cs_detail>("cs_detail",
		"groups", [](cs_detail& s) { return (uint32_t)s.groups; },
		"groups_count", [](cs_detail& s) { return (uint32_t)s.groups_count; },

		"x86", [](cs_detail& s) { return s.x86; }
	);

	G::Lua.new_usertype<cs_detail_c>("cs_detail_c",
		"x86", sol::readonly_property(&cs_detail_c::x86),
		"groups", sol::readonly_property(&cs_detail_c::groups),
		"groups_count", sol::readonly_property(&cs_detail_c::groups_count)
	);


	G::Lua.new_usertype<cs_insn_c>("cs_insn_c",
		//sol::meta_function::pairs, &cs_insn_c::pairs,
		"mnemonic", sol::readonly_property (&cs_insn_c::mnemonic),
		"address", sol::readonly_property(&cs_insn_c::address),
		"id", sol::readonly_property(&cs_insn_c::id),
		"size", sol::readonly_property(&cs_insn_c::size),
		"op_str", sol::readonly_property(&cs_insn_c::op_str),
		"bytes", sol::readonly_property(&cs_insn_c::bytes),

		"detail", sol::readonly_property(&cs_insn_c::detail)
		);

	G::Lua.new_usertype<cs_insn>("cs_insn",
		"address", [](cs_insn& s) { return (uint64_t)s.address; },
		"id", [](cs_insn& s) { return (uint32_t)s.id; },
		"size", [](cs_insn& s) { return (uint32_t)s.size; },
		"op_str", [](cs_insn& s) -> std::string { return (const char *)s.op_str; },
		"mnemonic", [](cs_insn& s) { return std::string(s.mnemonic); },
		"bytes", [](cs_insn& s) { return s.bytes; },

		"detail", [](cs_insn& s) { return s.detail; }
	);

	G::Lua.new_usertype<LuaCapstone>("LuaCapstone",
		sol::default_constructor,
		"set_platform", sol::overload(sol::resolve<uint32_t(uint32_t, uint32_t)>(&LuaCapstone::setplatform), sol::resolve<uint32_t(uint32_t, uint32_t, uint64_t)>(&LuaCapstone::setplatform)),
		"open", &LuaCapstone::open,
		//"open_from_file", &LuaCapstone::OpenFromFile
		"disasm", &LuaCapstone::disasm
		);

	G::Lua["ARCH_TYPE"] = G::Lua.create_table_with(
		"X86", CS_ARCH_X86
	);
	G::Lua["ARCH_MODE"] = G::Lua.create_table_with(
		"X32", CS_MODE_32,
		"X64", CS_MODE_64
	);


	G::Lua["capstone"] = LuaCapstone{ };
}

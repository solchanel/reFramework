#pragma once

struct cs_detail_c {
	cs_detail_c(cs_insn* e) : data(e) { }

	cs_x86 x86() const { return data->detail->x86; }
	uint8_t groups_count() const { return data->detail->groups_count; }
	std::vector<uint8_t> groups() const
	{
		std::vector<uint8_t> bytes;
		bytes.assign(data->detail->groups, data->detail->groups + data->detail->groups_count);
		return bytes;
	}

	cs_insn* data;
};

//struct cs_insn_c_iterator_state {
//	typedef std::vector<cs_insn_c*> it_t;
//	it_t it;
//	it_t last;
//
//	cs_insn_c_iterator_state(cs_insn_c& e) : it(e), last(e) { }
//};
 
struct cs_insn_c {
	cs_insn_c(cs_insn& e) : data(e), detail_data(&data) { }

	//static int pairs_next(lua_State* L)
	//{

	//}

	//static int pairs(lua_State* L)
	//{

	//}

	std::string mnemonic() const { return std::string(data.mnemonic); }
	std::string op_str() const { return std::string(data.op_str); }
	std::vector<uint8_t> bytes() const
	{
		std::vector<uint8_t> bytes;
		bytes.assign(data.bytes, data.bytes + sizeof(data.bytes));
		return bytes;
	}

	cs_detail_c* detail() 
	{ 
		if (!data.detail)
			return nullptr;
		return &detail_data; 
	}

	uint64_t address() const { return data.address; }
	uint32_t id() const { return data.id; }
	uint32_t size() const { return data.size; }

	cs_detail_c detail_data;
	cs_insn data;
};

class LuaCapstone
{
public:
	LuaCapstone();
	~LuaCapstone();

	uint32_t setplatform(uint32_t arch_type, uint32_t arch_mode);
	uint32_t setplatform(uint32_t arch_type, uint32_t arch_mode, uint64_t base_address);
	void open(std::string data);

	std::vector<cs_insn_c *> disasm();

private:


	uint8_t* disasm_data = nullptr;
	uint32_t disasm_data_size = 0;

	csh handle;
	uint64_t base_address = 0;

	std::vector<cs_insn_c *> disasm_ins;
};

namespace Capstone 
{
	typedef struct {
		cs_arch arch;
		cs_mode mode;
		unsigned char* code;
		size_t size;
		const char* comment;
		cs_opt_type opt_type;
		cs_opt_value opt_value;
	} platform_t;
}
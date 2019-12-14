#include "main.hpp"

LuaCapstone::LuaCapstone()
{

}

LuaCapstone::~LuaCapstone()
{
	disasm_ins.clear();
}

uint32_t LuaCapstone::setplatform(uint32_t arch_type, uint32_t arch_mode)
{
	return (uint32_t)cs_open((cs_arch)arch_type, (cs_mode)arch_mode, &this->handle);
}

uint32_t LuaCapstone::setplatform(uint32_t arch_type, uint32_t arch_mode, uint64_t base_address)
{
	this->base_address = base_address;
	return (uint32_t)cs_open((cs_arch)arch_type, (cs_mode)arch_mode, &this->handle);
}

void LuaCapstone::open(std::string data)
{
	if (disasm_data_size > 0)
		std::free(disasm_data);

	disasm_data = (uint8_t*)std::malloc(data.size());
	disasm_data_size = data.size() - 1;
	std::memcpy((void *)disasm_data, data.c_str(), disasm_data_size);
}

std::vector<cs_insn_c *> LuaCapstone::disasm()
{
	cs_insn* ins;
	uint32_t count = NULL;

	if ((count = cs_disasm(this->handle, disasm_data, disasm_data_size, base_address, 0, &ins)))
	{
		unsigned j;

		for (j = 0; j < count; j++) {
			printf("0x%" PRIx64 ":\t%s\t\t%s\t%d\n", ins[j].address, ins[j].mnemonic, ins[j].op_str, ins[j].bytes[1]);
		}

		printf("0x%" PRIx64 ":\n", ins[j - 1].address + ins[j - 1].size);
	}

	if (disasm_ins.size() > 0)
		disasm_ins.clear();

	for (unsigned i = 0; i < count; i++)
		disasm_ins.push_back(new cs_insn_c(ins[i]));

	cs_free(ins, count);
	return disasm_ins;
}

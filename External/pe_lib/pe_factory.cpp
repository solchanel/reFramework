#include "pe_factory.h"
#include "pe_properties_generic.h"

namespace pe_bliss
{
pe_base pe_factory::create_pe(std::istream& file, bool is_file_from_mem, bool read_debug_raw_data)
{
    return pe_base::get_pe_type(file) == pe_type_32
        ? pe_base(file, pe_properties_32(), is_file_from_mem, read_debug_raw_data)
        : pe_base(file, pe_properties_64(), is_file_from_mem, read_debug_raw_data);
}
}

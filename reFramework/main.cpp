#include "main.hpp"

namespace G
{
	sol::state Lua;
}

int LuaExceptionHandlerEx(lua_State* L, sol::optional<const std::exception&> maybe_exception, sol::string_view description)
{
	std::cout << "An exception occurred in a function, here's what it says ";
	if (maybe_exception)
	{
		std::cout << "(straight from the exception): ";
		const std::exception& ex = *maybe_exception;
		std::cout << ex.what() << std::endl;
	}
	else
	{
		std::cout << "(from the description parameter): ";
		std::cout.write(description.data(), description.size());
		std::cout << std::endl;
	}
	return sol::stack::push(L, description);
}

int main(int argc, char** argv)
{
	char LuaPath[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, LuaPath);

	std::sprintf(LuaPath, "%s\\run.lua", LuaPath);

	G::Lua.open_libraries();
	G::Lua.set_exception_handler(&LuaExceptionHandlerEx);
	LuaAPI::Init();
	
	try
	{
		sol::optional<sol::error> err = G::Lua.safe_script_file(LuaPath, sol::script_pass_on_error);
		if (err) std::cout << err->what() << std::endl;
	}
	catch (const sol::error & err)
	{
		std::cout << "sol::error: " << err.what() << std::endl;
	}
	catch (...)
	{
		std::exception_ptr crterr = std::current_exception();
		std::cout << "caught (...)" << std::endl;
	}


	_getch();
	return EXIT_SUCCESS;
}
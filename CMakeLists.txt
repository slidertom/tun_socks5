cmake_minimum_required(VERSION 3.9.0)
set(CMAKE_CXX_STANDARD 17)
set_property(GLOBAL PROPERTY USE_FOLDERS ON) 

macro(set_project_exe_mode)
	file(GLOB_RECURSE sources "*.cpp" "*.h" "*.c" "*.rc" "*.bmp" "*.cur" "*ico")
	set(root "${CMAKE_CURRENT_SOURCE_DIR}")
	source_group(TREE ${root} FILES ${sources})
	list(REMOVE_ITEM sources "${CMAKE_CURRENT_SOURCE_DIR}/build/CMakeFiles/${CMAKE_VERSION}/CompilerIdCXX/CMakeCXXCompilerId.cpp")
	list(REMOVE_ITEM sources "${CMAKE_CURRENT_SOURCE_DIR}/build/CMakeFiles/${CMAKE_VERSION}/CompilerIdC/CMakeCCompilerId.c")
	list(REMOVE_ITEM sources "${CMAKE_CURRENT_SOURCE_DIR}/build/CMakeFiles/feature_tests.c")
	source_group("" FILES ${sources})
	add_executable(${PROJECT_NAME} ${sources})
endmacro(set_project_exe_mode)

project(tunproxy)
set_project_exe_mode()

target_link_libraries(tunproxy)
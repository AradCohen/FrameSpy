cmake_minimum_required(VERSION 3.16)
project(FrameSpy)

set(CMAKE_CXX_STANDARD 14)

include_directories(".")
include_directories(FrameSpy PUBLIC /usr/local/include/tins/)
include_directories(FrameSpy PUBLIC /usr/local/include/pfs/)

# adding the tins's dir to linker directories
link_directories(FrameSpy /usr/local/lib/)

add_executable(FrameSpy main.cpp PidCollector.cpp)

#find_package(PythonLibs REQUIRED)
#include_directories(${PYTHON_INCLUDE_DIRS})
#target_link_libraries(FrameSpy PUBLIC ${PYTHON_LIBRARIES})

target_link_libraries(FrameSpy PUBLIC tins)
target_link_libraries(FrameSpy PUBLIC pfs)

cmake_minimum_required(VERSION 3.27)
project(vacdumper)

set(CMAKE_CXX_STANDARD 23)

add_library(vacdumper SHARED main.cpp
        patternscanner/scanner.cpp
        patternscanner/scanner.hpp
        minhook/buffer.cpp
        minhook/buffer.hpp
        minhook/hook.cpp
        minhook/MinHook.hpp
        minhook/trampoline.cpp
        minhook/trampoline.hpp
        minhook/hde/hde32.cpp
        minhook/hde/hde32.hpp
        minhook/hde/hde64.cpp
        minhook/hde/hde64.hpp
        minhook/hde/pstdint.hpp
        minhook/hde/table32.hpp
        minhook/hde/table64.hpp)

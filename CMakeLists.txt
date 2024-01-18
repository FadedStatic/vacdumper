cmake_minimum_required(VERSION 3.27)
project(vacdumper)

set(CMAKE_CXX_STANDARD 23)

add_library(vacdumper SHARED main.cpp
        patternscanner/scanner.cpp
        patternscanner/scanner.hpp
        minhook/buffer.c
        minhook/buffer.h
        minhook/hook.c
        minhook/MinHook.h
        minhook/trampoline.c
        minhook/trampoline.h
        minhook/hde/hde32.c
        minhook/hde/hde32.h
        minhook/hde/hde64.c
        minhook/hde/hde64.h
        minhook/hde/pstdint.h
        minhook/hde/table32.h
        minhook/hde/table64.h)

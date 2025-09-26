#!/bin/sh

CFLAGS="-std=c99 \
	-Wall -Wextra -Wpedantic \
	-fdiagnostics-color=always \
	-fstack-clash-protection \
	-fstack-protector-all \
	-fno-omit-frame-pointer \
	-fno-common \
	-Wfloat-equal \
	-Wformat=2 \
	-Wformat-truncation=2 \
	-Wformat-overflow \
	-Wstrict-aliasing=2 \
	-Wunused-parameter \
	-Wundef \
	-Wredundant-decls \
	-Wmissing-include-dirs \
	-Wshadow \
	-Wdouble-promotion \
	-Wlogical-op \
	-Wduplicated-branches \
	-Wduplicated-cond \
	-Walloc-zero \
	-Wnull-dereference \
	-Wcast-qual \
	-Wcast-align \
	-Wdate-time \
	-Wimplicit-fallthrough=2 \
	-Wjump-misses-init \
	-Wpacked \
	-Wnested-externs \
	-Wvla \
	-Wstack-protector \
	-Wold-style-definition \
	-Winit-self \
	-Wstrict-prototypes \
	-Wstringop-overflow=2 \
	-fsanitize=undefined,address,pointer-compare,pointer-subtract \
	-g3 -march=native"

gcc $CFLAGS register.c -o register
gcc $CFLAGS nested_frames.c -o nested_frames

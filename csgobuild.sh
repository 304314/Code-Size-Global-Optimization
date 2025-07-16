#!/bin/bash

ROOT_DIR="/codesize"
PROJECT_DIR="/codesize/csgo"
BUILD_DIR="/codesize/csgo/build"
INSTALL_DIR="/codesize/install"

mkdir -p "$BUILD_DIR" "$INSTALL_DIR"

cmake -S "$PROJECT_DIR/llvm" -B "$BUILD_DIR" -G "Unix Makefiles" \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="RISCV" \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_BUILD_TYPE=Release


cmake --build "$BUILD_DIR" --target install -j16

mkdir -p "$INSTALL_DIR/lib/clang-runtimes"
rm -rf "$INSTALL_DIR/lib/clang-runtimes/riscv32"
cp -r "$PROJECT_DIR/riscv32" "$INSTALL_DIR/lib/clang-runtimes/"
cp -r "$PROJECT_DIR/bm" "$ROOT_DIR/"

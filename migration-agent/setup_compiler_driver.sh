#!/bin/sh
pip install pyinstaller
rm -rf build/
rm -rf dist/
rm bishengai.spec
TARGET="bishengai"
SOURCE="src/compiler_driver.py"
pyinstaller --onefile $SOURCE --name $TARGET
export CC=`pwd`/dist/$TARGET
export CXX=$CC
export LLM_DEVELOPMENT=1
# export COMPILER_CHOICE="clang++" # "clang" for c; "clang++"" for c++
export LLM_DEBUG=1
export AUTO_ACCEPT=1 # not export-interactive window; export-automatically change
export LLM_API_TOKEN=   # add your api token here
~
~
~
~
~


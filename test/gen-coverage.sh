TEST_NAME=$1
OUT_DIR=$2
if [ -z "$OUT_DIR" ]; then
  OUT_DIR="tmp/coverage"
fi
BUILD_DIR=$3
if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR="build-clang-cov"
fi
$BUILD_DIR/run-test "$TEST_NAME"
if [ -f /usr/bin/llvm-profdata-18 ]; then
  PROFDATA_BIN=llvm-profdata-18
  COV_BIN=llvm-cov-18
else
  PROFDATA_BIN=llvm-profdata
  COV_BIN=llvm-cov
fi
$PROFDATA_BIN merge -sparse default.profraw -o run-test.profdata
$COV_BIN show -show-branches=percent -ignore-filename-regex=lib/dt/cli -ignore-filename-regex=3rdparty/ -format=html -output-dir=$OUT_DIR $BUILD_DIR/run-test -instr-profile=run-test.profdata

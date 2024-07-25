TEST_NAME=$1
SOURCE_FILE=$2
COMMAND=$3
BUILD_DIR=$4
if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR="build-clion-coverage"
fi
if [ -z "$COMMAND" ]; then
  COMMAND="show"
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
$COV_BIN $COMMAND $BUILD_DIR/run-test -instr-profile=run-test.profdata -sources "lib/dt/$SOURCE_FILE"
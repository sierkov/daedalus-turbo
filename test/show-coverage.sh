TEST_NAME=$1
SOURCE_FILE=$2
BUILD_DIR=$3
if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR="build-clion-coverage"
fi
$BUILD_DIR/run-test "$TEST_NAME"
llvm-profdata merge -sparse default.profraw -o run-test.profdata
llvm-cov show $BUILD_DIR/run-test -instr-profile=run-test.profdata -sources "lib/dt/$SOURCE_FILE"
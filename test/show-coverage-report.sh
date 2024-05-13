BUILD_DIR=$1
if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR="build-clion-coverage"
fi
$BUILD_DIR/run-test
llvm-profdata merge -sparse default.profraw -o run-test.profdata
llvm-cov report $BUILD_DIR/run-test -instr-profile=run-test.profdata
BUILD_DIR=$1
if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR="build-clion-coverage"
fi
if [ -f /usr/bin/llvm-profdata-18 ]; then
  PROFDATA_BIN=llvm-profdata-18
  COV_BIN=llvm-cov-18
else
  PROFDATA_BIN=llvm-profdata
  COV_BIN=llvm-cov
fi
$BUILD_DIR/run-test
$PROFDATA_BIN merge -sparse default.profraw -o run-test.profdata
$COV_BIN report --ignore-filename-regex=lib/dt/cli --ignore-filename-regex=3rdparty --ignore-filename-regex="\.test\.cpp$" $BUILD_DIR/run-test -instr-profile=run-test.profdata
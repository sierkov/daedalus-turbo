#! /bin/bash
BIN_PATH=../../src
DATA_PATH=/data/compressed
SSD_DEVICE=/dev/vda
test -f experiment.log && rm experiment.log
for i in `seq 1 5`; do
	echo "Run $i hdparm -t" | tee -a experiment.log
	hdparm -t $SSD_DEVICE | tee -a experiment.log
	for compressor in lz4 zstd; do
			for command in compress decompress; do
				echo "Run $i of $compressor $command" | tee -a experiment.log
				$BIN_PATH/$compressor $command $DATA_PATH | tee -a experiment.log
			done
	done
done

#! /bin/env bash
ulimit -n 32768
test -d ./log || mkdir ./log
for iter in 1 2 3 4 5; do
	for threads in 48 1 32 2 24 4 16 8; do
		for lz4 in "" "--lz4"; do
			echo "iter: $iter, threads: $threads, lz4: $lz4"
			sync; echo 3 > /proc/sys/vm/drop_caches
			echo "kernel caches flushed, starting monitoring and logging processes"
			dool --disk --cpu --io --freespace --ascii --noheaders &> log/run-$iter-$threads$lz4-dool.log 1 &
			bash -c "while true; do docker stats --no-stream >> log/run-$iter-$threads$lz4-docker-stats.log; sleep 1; done" &
			echo "starting the benchmark"
			docker run --rm -v /data/cardano-node/immutable:/data/chain -v $PWD:/workspace -v /data/index:/data/index dt /bin/bash -c "sudo chown -R dev:dev /data /workspace; ./create-index /data/chain /data/index --log --threads=$threads $lz4"
			echo "stopping monitoring and logging processes"
			jobs -p | xargs -r kill
		done
	done
done

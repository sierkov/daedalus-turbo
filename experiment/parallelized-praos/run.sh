#! /bin/env bash
ulimit -n 32768
test -d ./log || mkdir ./log
for iter in `seq 1 3`; do
    for threads in 24 4 16 8 2; do
        echo "iter: $iter, threads: $threads"
        sync; echo 3 > /proc/sys/vm/drop_caches
        echo "kernel caches flushed, starting monitoring and logging processes"
        bash -c "while true; do docker stats --no-stream >> /data/cardano/dt-validate-docker-stats-$iter-$threads.log; sleep 1; done" &
        echo "starting the benchmark"
        docker run --cpus $threads --rm -v /data/cardano:/data/cardano dt /bin/bash -c "sudo chown -R dev:dev /data; DT_LOG=/data/cardano/dt-validate-$iter-$threads.log DT_WORKERS=$threads ./dt revalidate /data/cardano"
        echo "stopping monitoring and logging processes"
        jobs -p | xargs -r kill
    done
done
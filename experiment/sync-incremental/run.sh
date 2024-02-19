#! /bin/env bash
set -e
ulimit -n 32768
test -d ./log || mkdir ./log
test -d /data/cardano && rm -f /data/cardano/*.log
max_epoch=465
for iter in `seq 1 5`; do
    for threads in 24 8; do
        for epochs in 36 6 1; do
            let "start_epoch=$max_epoch - $epochs"
            echo "iter: $iter, threads: $threads, epochs: $epochs"
            echo "preparing the data"
            docker run --cpus $threads --rm -v /data/cardano:/data/cardano dt /bin/bash -c "sudo chown -R dev:dev /data; DT_LOG=/data/cardano/dt-truncate-$iter-$threads-$epochs.log DT_WORKERS=$threads ./dt truncate /data/cardano $start_epoch"
            docker run --cpus $threads --rm -v /data/cardano:/data/cardano dt /bin/bash -c "sudo chown -R dev:dev /data; DT_LOG=/data/cardano/dt-catchup-$iter-$threads-$epochs.log DT_WORKERS=$threads ./dt sync-http /data/cardano --max-epoch=$start_epoch"
            sync; echo 3 > /proc/sys/vm/drop_caches
            echo "kernel caches flushed, starting monitoring and logging processes"
            bash -c "while true; do docker stats --no-stream >> /data/cardano/dt-sync-http-docker-stats-$iter-$threads-$epochs.log; sleep 1; done" &
            echo "starting the benchmark"
            docker run --cpus $threads --rm -v /data/cardano:/data/cardano dt /bin/bash -c "sudo chown -R dev:dev /data; DT_LOG=/data/cardano/dt-incr-sync-$iter-$threads-$epochs.log DT_WORKERS=$threads ./dt sync-http /data/cardano --max-epoch=$max_epoch"
            echo "stopping monitoring and logging processes"
            jobs -p | xargs -r kill
        done
    done
done
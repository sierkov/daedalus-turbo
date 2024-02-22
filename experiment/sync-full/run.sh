#! /bin/env bash
ulimit -n 32768
test -d ./log || mkdir ./log
test -d /data/cardano && rm -f /data/cardano/*.log
for iter in `seq 1 3`; do
    for threads in 24 8; do
        echo "iter: $iter, threads: $threads"
        test -d /data/cardano && rm -rf /data/cardano/{compressed,index,validate}
        sync; echo 3 > /proc/sys/vm/drop_caches
        echo "kernel caches flushed, starting monitoring and logging processes"
        bash -c "while true; do docker stats --no-stream >> /data/cardano/dt-sync-http-docker-stats-$iter-$threads.log; sleep 1; done" &
        echo "starting the benchmark"
        docker run --cpus $threads --rm -v /data/cardano:/data/cardano dt /bin/bash -c "sudo chown -R dev:dev /data; DT_LOG=/data/cardano/dt-sync-http-$iter-$threads.log DT_WORKERS=$threads ./dt sync-http /data/cardano --max-epoch=465"
        echo "stopping monitoring and logging processes"
        jobs -p | xargs -r kill
    done
done
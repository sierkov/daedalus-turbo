#! /bin/env bash
for iter in 1 2 3 4 5; do
    echo "Iteration $iter"
    test -f /data/cardano-wallet/she* || rm /data/cardano-wallet/she*
    sync; echo 3 > /proc/sys/vm/drop_caches
    echo "kernel caches flushed, starting the benchmark"
    docker-compose up -d
    echo "waiting for 15 seconds to let cardano-node and cardano-wallet to start"
    sleep 15
    echo "starting dool in background"
    dool --disk --cpu --io --freespace --ascii --noheaders &> log/run-$iter-dool.log 1 &
    echo "starting docker stats collection in background"
    bash -c "while true; do docker stats --no-stream >> log/run-$iter-docker-stats.log; sleep 1; done" &
    echo "starting measure.js"
    node measure.js | tee log/measure-$iter.log
    echo "killing background jobs"
    jobs -p | xargs -r kill
    docker-compose down
done

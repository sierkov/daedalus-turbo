# Experiments

## From "Parallelized Ouroboros Praos" paper
- [parallelized-praos](./parallelized-praos) - measure the local validation performance of Parallelized Ouroboros Praos;
- [sync-cardano-node](./sync-cardano-node) - measure the end-to-end synchronization time of Cardano Node;
- [sync-full](./sync-full) - measure the end-to-end synchronization time of Daedalus Turbo;
- [sync-incremental](./sync-incremental) - measure the incremental synchronization time of Daedalus Turbo;
- [sync-mithril](./sync-mithril) - measure the end-to-end synchronization time of Mithril.

## From "Highly-parallel wallet-history reconstruction in the Cardano blockchain" paper:
- [bench-algo](./bench-algo/) - the code to measure the performance of the highly-parallel wallet-history-reconstruction method;
- [bench-cardano-wallet](./bench-cardano-wallet/) - the code to measure the performance of wallet-history reconstruction by Cardano wallet.

## From "Scalability of Bulk Synchronization in the Cardano Blockchain" paper
- [cardano-peer-discovery](./cardano-peer-discovery/) - capture and analyze network traffic during Cardano Node synchronization from scratch;
- [compression](./compression/) - measure the compression ratio and compression/decompression speed of per-chunk [Zstandard](https://github.com/facebook/zstd) compression.

# Replicating the benchmarking environment
To ensure that all experiments are reproducible, they were performed
on bare-metal servers rented at [Vultr](https://www.vultr.com/products/bare-metal).
Bare-metal servers reduce the possibility of alternative workloads affecting experiment results.
Specifically, a server with a 24-core AMD EPYC 7443P CPU was used.
This variant was chosen to better highlight the benefits of parallel processing.
At the same time, since the primary users of Daedalus wallets are consumers, 
where applicable, the experiments were additionally run with
a reduced thread count of eight to simulate consumer-grade laptops.

### Setup

Start a new bare-metal server with an AMD EPYC 7443P CPU running under Ubuntu 22.04 LTS. Servers with exactly the same configuration as in the paper can be rented at [Vultr](https://www.vultr.com/products/bare-metal).

Create a raid0 disk array and mount it under /data:
```
mdadm --create --verbose /dev/md1 --level=0 --raid-devices=2 /dev/nvme0n1 /dev/nvme1n1
mkfs -t ext4 /dev/md1
mkdir /data
mount /dev/md1 /data
```

Install the docker-compose package:
```
apt update
apt install -y docker-compose
```

## From "Parallelized Ouroboros Praos" paper

Install the additional necessary packages:

```
/bin/bash <(curl -sL https://deb.nodesource.com/setup_20.x)
apt install -y nodejs
```

Download the source code and build the test docker image:
```
git clone https://github.com/sierkov/daedalus-turbo dt
cd dt
git checkout parallelized-ouroboros-praos
docker build -t dt -f Dockerfile.test .
```

To run an individual experiment, such as [parallelized-praos](./parallelized-praos), do:
```
cd experiment/parallelized-praos
bash run.sh
```

## From "Highly-parallel wallet-history reconstruction in the Cardano blockchain" paper:

Install the additional necessary packages:
```
cd /root
git clone https://github.com/scottchiefbaker/dool
cd dool
python3 install.py
/bin/bash <(curl -sL https://deb.nodesource.com/setup_18.x)
apt install -y nodejs
```

Copy raw blockchain data from a Cardano Node instance:
```
mkdir /data/cardano-node
cp -r /your-cardano-node/immutable /data/cardano-node
```
Note: the benchmarks in the paper were made when the tip of the Cardano blockchain was at slot number 77374448.

Optional: copy the ledger state from a Cardano Node instance - needed only if you plan to benchmark against Cardano Wallet:
```
cp -r /your-cardano-node/ledger /data/cardano-node
```

Optional: copy pooldb from a Cardano Wallet instance - needed only if you plan to benchmark against Cardano Wallet:
```
mkdir /data/cardano-wallet
cp /your-cardano-wallet/stake-pools.sqlite /data/cardano-wallet
```

Download the source code and build the docker image:
```
git clone https://github.com/sierkov/daedalus-turbo dt
cd dt
git checkout release-20230201
docker build -t dt -f Dockerfile.test .
```

Create lz4 compressed copies of all ImmutableDB chunks:
```
docker run --rm -v /data/cardano-node/immutable:/immutable dt bash -c "sudo chown -R dev:dev /immutable; ./lz4 compress /immutable"
```


# About

The objective of Daedalus Turbo project is to drastically (>=10x) improve the blockchain synchronization speed of the Daedalus wallet, the primary fully-decentralized wallet of Cardano blockchain.

At the moment, this repository contains an implementation of the highly-parallel wallet-history reconstruction algorithm described in [2023_Sierkov_WalletHistoryReconstruction](./doc/2023_Sierkov_WalletHistoryReconstruction.pdf) paper.

As the project moves forwards, other components will be added. To better understand the project's scope read the discussion section of [2023_Sierkov_WalletHistoryReconstruction](./doc/2023_Sierkov_WalletHistoryReconstruction.pdf) paper.

# Requirements
- A local copy of ImmutableDB generated by Cardano Node. In particular, the *.chunk files are necessary.
  You should be able to specify a path to your local copy of it.
- An installation of Docker. You should be comfortable with using Docker containers.
  When benchmarking the code, please ensure that all your host's CPUs are available within the docker container!
- 20GB of free disk space - 10GB for the indices that Daedalus Turbo creates
  and another 10GB for temporary files, which will be deleted once the indices are created.
- The required RAM depends on the number of threads that one plans to run.
  Each additional thread requires about 200MB of RAM for the create-index process.
  So, to run 48 threads about 8GB of RAM are needed.
- A Cardano stake address for which you can verify a list of associated transactions using an alternative mechanism,
  such as Daedalus wallet itself, one of the light wallets or one of the blockchain explorer websites.
  The stake key must be in BECH32 format for Cardano Reward addresses: a text string starting with the "stake1" prefix.

# Supported features

For the initial-preview version of the algorithm, only the minimal set of Cardano features is supported:
- Shelley-era addresses with an explicit stake-key hash (type 1).
- ADA-only transactions.
- Withdrawals-only for staking rewards; inflows are ignored.

As the project matures the list of supported Cardano features is expected to grow.

# How to

## Test wallet-history reconstruction

Clone this repository and make it your working directory
```
git clone https://github.com/sierkov/daedalus-turbo.git dt
cd dt
```

Run the following commands to prepare and start a container:
```
docker build -t dt -f Dockerfile.test .
docker run -it --rm -v /your-cardano-node/immutable:/data/immutable -v /your-local-folder-in-which-to-save-indices:/data/indices dt
```

Within the container run the following commands to create the indices
and perform a transaction-history reconstruction for your a given stake key:
```
chown -R dev:dev /data/indices
./create-index /data/immutable /data/indices
./search-index /data/immutable /data/indices stake1XXXXXX
```
The second command will output to the console a list of the transactions related to that stake key along with their metadata. If the transactions do not match your alternative source,
please double check that the copy of the ImmutableDB that you've passed to the command
is up to date!

## Reproduce benchmarks from the paper

Start a new AMD EPYC 7443P instance with Ubuntu 22.04 LTS as the image.
An instance with exactly the same configuration as in the paper can be rented at [Vultr](https://www.vultr.com/products/bare-metal).

create a raid0 disk array and mount it under /data:
```
mdadm --create --verbose /dev/md1 --level=0 --raid-devices=2 /dev/nvme0n1 /dev/nvme1n1
mkfs -t ext4 /dev/md1
mkdir /data
mount /dev/md1 /data
```

install the necessary packages:
```
apt install -y docker-compose
cd /root
git clone https://github.com/scottchiefbaker/dool
cd dool
python3 install.py
/bin/bash <(curl -sL https://deb.nodesource.com/setup_18.x)
apt install -y nodejs
```

copy raw blockchain data from a cardano-node instance:
```
mkdir /data/cardano-node
cp -r /your-cardano-node/immutable /data/cardano-node
```

Optional: copy the ledger state a cardano-node instance - needed only if you plan to benchmark against cardano-wallet:
```
cp -r /your-cardano-node/ledger /data/cardano-node
```

Optional: copy pooldb from a cardano-wallet instance - needed only if you plan to benchmark against cardano-wallet:
```
mkdir /data/cardano-wallet
cp -r /your-cardano-wallet/stake-pools.sqlite /data/cardano-wallet
```

clone this repository and build the docker image:
```
git clone https://github.com/sierkov/daedalus-turbo dt
cd dt
docker build -t dt -f Dockerfile.test .
```

create lz4 compressed copies of all immutabledb chunks:
```
docker run --rm -v /data/cardano-node/immutable:/immutable dt ./lz4-compress /immutable
```

run the benchmark:
```
cd experiments/bench-algo
bash run-bench.sh
```
Expect the bench-algo benchmark to take about three hours when using exactly
the same hardware config.
All experiment data will be saved into log directory next to the run-bench.sh script.

Optional run the benchmark of Cardano Wallet:
```
cd experiments/bench-cardano-wallet
bash run-bench.sh
```
Expect the bench-cardano-wallet benchmark to take about ten hours when using exactly
the same hardware config.
All experiment data will be saved into log directory next to the run-bench.sh script.

# Performance notes
- The performance of the method depends on the speed of your local storage.
  The more cores you have, the higher it should be. The necessary storage
throughput should increase by 250 megabytes/sec for every additional CPU thread.
  So, if you plan to run 20 threads, ensure your SSD can reach 5000 megabytes/sec in the sequential read performance.
- The performance of the method depends on the number of CPU cores you have.
  To fully benefit from the acceleration, benchmarking with 16+ cores is recommended.
- The use of docker volumes can lead to lower performance on some platforms, such as Windows.
  So, when benchmarking to reproduce the paper's results,
  please use exactly the same setup as presented in the paper:
  Ubuntu Linux 22.04 LTS as your host OS.
  
* Benchmarking Edabits with Docker

Run the following commands:

```bash
cd swanky
docker build -f docker/Dockerfile -t swanky .
docker compose -f docker/docker-compose-edabits.yaml up --abort-on-container-exit
```

The results of the benchmarks are stored in `/tmp/bench_result.txt`

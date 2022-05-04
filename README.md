# netproc
Command line tool for monitoring and dumping connections with process names.

## Usage

```
netproc.py [-h] [--stop-iteration STOP_ITERATION] [--dump-freq DUMP_FREQ] [--sleep-time SLEEP_TIME] output

Monitor and dump connections with IP mapping to processes they belong. Only unique connections.

positional arguments:
  output                Name and path for output csv file.

optional arguments:
  -h, --help            show this help message and exit
  --stop-iteration STOP_ITERATION
                        How many iterations will proceed until stopped, -1 for infinite. (default=-1)
  --dump-freq DUMP_FREQ
                        After how many iterations dump finished connections to csv. (default=10)
  --sleep-time SLEEP_TIME
                        Sleep time after each monitoring iteration.
```

#!/bin/bash

# Run all Python scripts in parallel and output to both terminal and log files
sudo python3 dos.py | tee dos.log &
sudo python3 r2l.py | tee r2l.log &
sudo python3 scan.py | tee scan.log &

# Wait for all background processes to complete
wait


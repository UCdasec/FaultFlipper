#!/bin/bash

COMMANDS=$@
if [ -z "$COMMANDS" ]; then
    COMMANDS="bash"
fi

docker run \
    --ulimit core=0 \
    --rm \
    -it \
    -v ./:/code/FaultFlipper/:rw \
    -w /code/FaultFlipper \
    fault-flipper \
    $COMMANDS

# Run performance analysis
# docker run \
#     --ulimit core=0 \
#     --rm \
#     -it \
#     --cap-add=SYS_PTRACE \
#     -u $(id -u):$(id -g) \
#     -v ./:/code/FaultFlipper/:rw \
#     -w /code/FaultFlipper \
#     fault-flipper \
#     py-spy record --native --subprocesses --idle -o performance_data.svg -- $COMMANDS

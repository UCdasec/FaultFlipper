#!/bin/bash

COMMANDS=$@
if [ -z "$COMMANDS" ]; then
    COMMANDS="bash"
fi

docker run \
    --ulimit core=0 \
    --rm \
    -it \
    -u $(id -u) \
    -v ./:/code/FaultFlipper/:rw \
    -w /code/FaultFlipper \
    fault-flipper \
    $COMMANDS

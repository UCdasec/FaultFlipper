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

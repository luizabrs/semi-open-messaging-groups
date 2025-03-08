#!/bin/bash

DOCKERCMD=${DOCKER:-podman}
BASENAME=mr-impl
CANARY=.container_run

if [ -f "$CANARY" ]; then
  # canary is here, need to rebuild
  bash build.sh
fi
touch $CANARY
$DOCKERCMD run -it \
  --name ${BASENAME}-container ${BASENAME}-image

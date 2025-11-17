#!/bin/bash

if [ $# -lt 1 -o "$1" != "-f" ]; then
    echo "Requires confirmation. Run again, passing the argument to force the 'docker system prune -a' operation: -f"
    exit 1
fi

docker compose down
docker system prune -a $1

#!/usr/bin/env bash

python3 -m pip install --user -r scripts/basic.requirements.txt
make -j$(nproc)

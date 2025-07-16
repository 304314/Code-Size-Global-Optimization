#!/bin/bash

for dir in 4743 bm1 bm2 bm3; do
  echo "Building in $dir..."
  if [ -d "$dir" ]; then
    cd "$dir" || { echo "Failed to enter $dir"; exit 1; }
    make
    cd - > /dev/null
  else
    echo "Directory $dir does not exist!"
  fi
done


#!/bin/sh
NUM_PARTIES=2
LOG_PREFIX=stdout
for (( i = 0; i <= $NUM_PARTIES; i++ )) 
do
  echo "Running PID=$i"
  CMD="PID=$i go run sftest.go | tee ${LOG_PREFIX}_party${i}.txt"
  if [ $i = $NUM_PARTIES ]; then
    eval $CMD
  else
    eval $CMD &
  fi
done
#!/bin/sh



export MALLOC_ARENA_MAX=2



export NODE_OPTIONS="--max-old-space-size=48 --optimize-for-size"



exec node index.js 

#!/bin/sh
cmake . && make && ./mr_impl 2>benchmarks.json
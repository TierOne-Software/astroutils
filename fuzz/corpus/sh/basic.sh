#!/bin/sh
echo "hello $world"
for i in 1 2 3; do echo $i; done
if [ -n "$x" ]; then echo set; elif true; then :; else echo unset; fi

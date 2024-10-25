#!/bin/bash


export PYTHONUNBUFFERED=1

pylint *.py rfidiot | tee PYLINT.txt

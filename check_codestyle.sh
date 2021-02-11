#!/bin/sh

find -name '*.py' | xargs flake8 --max-line-length=100

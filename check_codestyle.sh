#!/bin/sh

find -name '*.py' | xargs flake8

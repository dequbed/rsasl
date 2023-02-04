#!/usr/bin/env bash

if [[ ${DRY_RUN} == "true" ]];
then
    echo "================================================"
    echo "DRY_RUN SET, ONLY PRINTING THE PLANNED ACTIONS!!"
    echo "================================================"
    echo "-- COMMAND LIST START --"
    echo git stash
    echo git flow release start $@
    echo git stash pop
    echo git add Cargo.toml CHANGELOG.md
    echo "-- COMMAND LIST END --"
else
    git stash
    git flow release start $@
    git stash pop
    git add Cargo.toml CHANGELOG.md
fi

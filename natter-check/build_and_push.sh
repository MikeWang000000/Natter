#!/bin/bash
set -e
natter_check_repo="nattertool/check"
natter_check_ver=$(python3 -Bc 'print(__import__("natter-check").__version__)')
[ "dev" = $(echo "$natter_check_ver" | cut -d- -f2) ] && natter_check_ver="dev"

function tag_natter_check()
{
    tag="$1"
    new_tags=("${@:2}")
    cmd=()
    for new_tag in "${new_tags[@]}"; do
        cmd+=("-t")
        cmd+=("$natter_check_repo:$new_tag")
    done
    docker buildx imagetools create "${cmd[@]}" "$natter_check_repo:$tag"
}

function build_and_push()
{
    docker buildx build --push --tag "$natter_check_repo:dev" --platform linux/amd64,linux/arm64 .
}

function tag_release()
{
    tag_natter_check    dev "$natter_check_ver" latest
}


build_and_push
if [ "$1" == "release" ]; then
    tag_release
fi

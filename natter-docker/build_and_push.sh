#!/bin/bash
set -e
natter_repo="nattertool/natter"
natter_ver=$(cd .. && python3 -Bc 'print(__import__("natter").__version__)')
[ "dev" = $(echo "$natter_ver" | cut -d- -f2) ] && natter_ver="dev"

function push_natter_manifest()
{
    tag="$1"
    docker manifest create "$natter_repo:$tag" \
        "$natter_repo:$tag-amd64" \
        "$natter_repo:$tag-arm64"
    docker manifest push "$natter_repo:$tag"
    docker manifest rm "$natter_repo:$tag"
}

function tag_natter()
{
    tag="$1"
    new_tags=("${@:2}")
    cmd=()
    for new_tag in "${new_tags[@]}"; do
        cmd+=("-t")
        cmd+=("$natter_repo:$new_tag")
    done
    docker buildx imagetools create "${cmd[@]}" "$natter_repo:$tag"
}

function build_and_push()
{
    docker compose build --no-cache

    docker push "$natter_repo" --all-tags

    push_natter_manifest    dev-debian
    push_natter_manifest    dev-alpine
    push_natter_manifest    dev-openwrt
    push_natter_manifest    dev-minimal

    tag_natter  dev-debian  dev
}

function tag_release()
{
    tag_natter  dev-debian  "$natter_ver-debian"    debian  "$natter_ver"   latest
    tag_natter  dev-alpine  "$natter_ver-alpine"    alpine
    tag_natter  dev-openwrt "$natter_ver-openwrt"   openwrt
    tag_natter  dev-minimal "$natter_ver-minimal"   minimal
}


build_and_push
if [ "$1" == "release" ]; then
    tag_release
fi

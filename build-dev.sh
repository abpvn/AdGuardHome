#!/bin/sh
if [ "$VERSION" = '' ]
then
    if [ "$BASE_VERSION" = '' ]
    then
        BASE_VERSION='v0.108.9'
        readonly BASE_VERSION
    fi
    commit_number="$( git rev-list --count $BASE_VERSION..HEAD )"
    readonly commit_number

    # The development builds are described with a combination of unset semantic
    # version, the commit's number within the branch, and the commit hash, e.g.:
    #
    #   v0.108.0-d.5+a1b2c3d4
    #
    version="$BASE_VERSION-d.${commit_number}+$( git rev-parse --short HEAD )"
else
    version="$VERSION"
fi
echo "$version"
make GOOS='linux' GOARCH='amd64' VERSION="$version"
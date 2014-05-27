#!/bin/bash

function usage() {
    echo "tinit <token> [ccache-file]"
    exit 1
}

function tinit() {
    token="$1"
    result_cc="$2"

    principal=`tlist $token | awk -F: '{print $2}'`
    echo "Will kinit with token for $principal"

    armor_cc=/tmp/krb5cc_armor.$$
    kinit -c $armor_cc -n
    if [ $? != 0 ]; then
        echo "Failed to obtain armor ticket"
        exit 1
    fi
    #echo /usr/local/bin/kinit -T $armor_cc -c $result_cc -X token=$token $principal
    /usr/local/bin/kinit -T $armor_cc -c $result_cc -X token=$token $principal
    if [ $? -ne 0 ]; then
        echo "Failed to obtain tgt ticket with token"
        rm -rf $armor_cc
        exit 1
    fi
    
    echo "Successfully obtained tgt in $result_cc cache file with token"
    rm -rf $armor_cc
}

# Main

token=""
result_cc="/tmp/krb5cc_tinit.$$"

if [ $# -gt 0 ]; then
    token="$1"
elif [ $# -gt 1 ]; then
    result_cc="$2"
else
    usage
fi

tinit $token $result_cc
exit 0

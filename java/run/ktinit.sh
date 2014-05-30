#!/bin/bash

function usage() {
    echo "This tool uses token to authenticate to KDC and obtains tgt for you. "
    echo "ktinit [-t token | -T token-cache-file] [-c kerb-ccache-file]"
    echo "      when no token specified, ~/.tokenauth.token will be used by default"
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
    
    cc_opt=""
    if [ X"$result_cc" != X ]; then
	cc_opt="-c $result_cc"
    fi

    /usr/local/bin/kinit -T $armor_cc $cc_opt -X token=$token $principal
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
token_cache=""
#result_cc="/tmp/krb5cc_tinit.$$"

while [[ $# > 1 ]]; do
    key="$1"
    shift

    case $key in
	-t)
	    token="$1"
	    shift
	    ;;
	-T)
	    token_cache="$1"
	    shift
	    ;;
	-c)
	    result_cc="$1"
	    shift
	    ;;
	*)
	    usage
	    ;;
    esac
done

if [[ X"$token" != X &&  X"$token_cache" != X ]]; then
    echo "Either token or token-cache can be specified, not both"
    usage
fi

if [ X"$token" = X ]; then    
    if [ X"$token_cache" = X ]; then
	cd && homedir=`pwd` && cd -
	token_cache="$homedir/.tokenauth.token"
    fi
    if [ -f $token_cache ]; then
	token=`cat ~/.tokenauth.token`
    fi
fi
if [ X"$token" = X ]; then
    echo "No token is available by default. Please specify your token either via -t or -T"
    usage
fi

tinit $token $result_cc
exit 0

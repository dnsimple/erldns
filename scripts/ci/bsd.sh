#!/bin/sh
# Installs OTP and rebar3 in a BSD CI VM and runs socket_SUITE.
#
# Not `make test`: these run emulated, and everything host-independent is
# already enforced on the Linux legs. The platforms disagree on where Erlang
# lands and what it is called, so install and then discover: a package
# reshuffle then fails here instead of testing on a stale OTP.
set -eu

: "${OTP_MAJOR:?OTP_MAJOR must be set}"
: "${REBAR3_VSN:?REBAR3_VSN must be set}"
SHIM="${PWD}/.ci-bin"

# git: rebar3 resolves every test-profile dep, one of which is a git dep.
case "$(uname -s)" in
    FreeBSD)
        sudo pkg install -y git curl "erlang-runtime${OTP_MAJOR}" </dev/null ||
            sudo pkg install -y git curl erlang </dev/null
        ;;
    OpenBSD)
        sudo pkg_add -I git curl </dev/null || true
        # Plain versioned stems rather than branches, so erlang%27 selects nothing.
        pkg=$(pkg_info -Q erlang | grep -E '^erlang-[0-9]' | tail -1 || true)
        if [ -n "${pkg}" ]; then
            sudo pkg_add -I "${pkg}" </dev/null || true
        fi
        # The default login class caps the data segment below what the BEAM
        # allocators reserve at startup.
        # shellcheck disable=SC3045  # OpenBSD's /bin/sh is ksh, which has ulimit -d
        ulimit -d unlimited 2>/dev/null || true
        ;;
    NetBSD)
        # pkgsrc installs under /usr/pkg. Refresh the index first, or pkgin can
        # sit waiting on a mirror.
        sudo pkgin -y update </dev/null || true
        sudo pkgin -y install git curl erlang </dev/null || true
        ;;
    *)
        echo "unsupported platform: $(uname -s)" >&2
        exit 1
        ;;
esac

candidates() {
    ls /usr/local/lib/erlang*/bin/erl /usr/pkg/lib/erlang*/bin/erl 2>/dev/null || true
    ls /usr/local/bin/erl[0-9]* /usr/pkg/bin/erl 2>/dev/null || true
    command -v erl 2>/dev/null || true
}

ERL=""
for candidate in $(candidates); do
    release=$("${candidate}" -noshell \
        -eval 'io:format("~s",[erlang:system_info(otp_release)]),halt().' 2>/dev/null || echo 0)
    case "${release}" in
        '' | *[!0-9]*) continue ;;
    esac
    if [ "${release}" -ge 27 ]; then
        ERL="${candidate}"
        break
    fi
done

if [ -z "${ERL}" ]; then
    echo "no OTP 27 or newer found among:" >&2
    candidates >&2
    ls -d /usr/local/bin/*erl* /usr/pkg/bin/*erl* /usr/local/lib/erlang* /usr/pkg/lib/erlang* >&2 ||
        true
    exit 1
fi
echo "using ${ERL}"

# rebar3 calls erl and escript by their plain names; OpenBSD suffixes them.
BINDIR=$(dirname "${ERL}")
SUFFIX=$(basename "${ERL}" | sed 's/^erl//')
mkdir -p "${SHIM}"
for tool in erl erlc escript; do
    if [ -x "${BINDIR}/${tool}${SUFFIX}" ]; then
        ln -sf "${BINDIR}/${tool}${SUFFIX}" "${SHIM}/${tool}"
    fi
done

curl -fsSLo "${SHIM}/rebar3" \
    "https://github.com/erlang/rebar3/releases/download/${REBAR3_VSN}/rebar3"
chmod +x "${SHIM}/rebar3"
export PATH="${SHIM}:${PATH}"

rebar3 compile
rebar3 ct --suite=test/socket_SUITE --cover=false

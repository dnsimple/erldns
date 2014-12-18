%% Copyright (c) 2014, SiftLogic LLC
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(erldns_crypto).


-export([encrypt/3, decrypt/3]).

%% @doc This module is slightly modified from the refrenced project. This project is under MIT license.
%% @see https://github.com/YangXin/tcp_channel

align(Data, Align) ->
    Len = byte_size(Data),
    R = Len rem Align,
    Pad = case R of
              0 ->
                  <<>>;
              R1 ->
                  R2 = (Align - R1) * 8,
                  <<0:R2>>
          end,
    <<Data/binary, Pad/binary>>.

aes_cbc128_key(Key) when is_list(Key) ->
    Key1 = list_to_binary(Key),
    aes_cbc128_key(Key1);
aes_cbc128_key(Key) when is_binary(Key)->
    case byte_size(Key) of
        16 ->
            Key;
        32 ->
            Key;
        _Other ->
            crypto:hash(md5, Key)
    end.

aes_cbc128_vec(Vec) when is_list(Vec) ->
    Vec1 = list_to_binary(Vec),
    aes_cbc128_vec(Vec1);
aes_cbc128_vec(Vec) when is_binary(Vec) ->
    case byte_size(Vec) of
        16 ->
            Vec;
        _Other ->
            crypto:hash(md5, Vec)
    end.

encrypt(Key, Vec, Data) ->
    Key1 = aes_cbc128_key(Key),
    Vec1 = aes_cbc128_vec(Vec),
    Len = byte_size(Data),
    Data1 = align(Data, 16),
    Data2 = crypto:block_encrypt(aes_cbc128, Key1, Vec1, Data1),
    <<Len:32, Data2/binary>>.

decrypt(Key, Vec, Data) ->
    <<Len:32, Data1/binary>> = Data,
    Key1 = aes_cbc128_key(Key),
    Vec1 = aes_cbc128_vec(Vec),
    Data2 = crypto:block_decrypt(aes_cbc128, Key1, Vec1, Data1),
    <<Data3:Len/binary, _Left/binary>> = Data2,
    Data3.
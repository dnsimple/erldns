-module(erldns_admin_auth_middleware).
-moduledoc false.

-behaviour(cowboy_middleware).

-export([execute/2]).

-spec execute(Req, Env) -> {ok, Req, Env} | {stop, Req} when
    Req :: cowboy_req:req(),
    Env :: cowboy_middleware:env().
execute(Req0, #{credentials := {Username, Password}} = Env) ->
    case is_authorized(Req0, Username, Password) of
        true ->
            {ok, Req0, Env};
        {false, WwwAuthenticateHeader} ->
            Req1 = set_www_authenticate_header(Req0, WwwAuthenticateHeader),
            Req2 = maybe_delete_resp_header(Req1),
            Req3 = reply_unauthorized(Req2),
            {stop, Req3}
    end.

-spec is_authorized(cowboy_req:req(), binary(), binary()) -> true | {false, iodata()}.
is_authorized(Req, ValidUsername, ValidPassword) ->
    case cowboy_req:parse_header(~"authorization", Req) of
        {basic, GivenUsername, GivenPassword} ->
            is_binary_of_equal_size(GivenUsername, ValidUsername) andalso
                is_binary_of_equal_size(GivenPassword, ValidPassword) andalso
                crypto:hash_equals(GivenUsername, ValidUsername) andalso
                crypto:hash_equals(GivenPassword, ValidPassword) orelse
                {false, ~"basic realm=\"erldns admin\""};
        _ ->
            {false, ~"basic realm=\"erldns admin\""}
    end.

-spec is_binary_of_equal_size(term(), term()) -> boolean().
is_binary_of_equal_size(Bin1, Bin2) ->
    is_binary(Bin1) andalso is_binary(Bin2) andalso byte_size(Bin1) =:= byte_size(Bin2).

-spec set_www_authenticate_header(cowboy_req:req(), iodata()) -> cowboy_req:req().
set_www_authenticate_header(Req, WwwAuthenticateHeader) ->
    cowboy_req:set_resp_header(~"www-authenticate", WwwAuthenticateHeader, Req).

-spec maybe_delete_resp_header(cowboy_req:req()) -> cowboy_req:req().
maybe_delete_resp_header(Req) ->
    case cowboy_req:has_resp_body(Req) of
        true -> Req;
        false -> cowboy_req:delete_resp_header(~"content-type", Req)
    end.

-spec reply_unauthorized(cowboy_req:req()) -> cowboy_req:req().
reply_unauthorized(Req) ->
    cowboy_req:reply(401, Req).

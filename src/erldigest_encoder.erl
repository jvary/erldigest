-module(erldigest_encoder).

-export([decode_challenge_headers/1,
         encode_response_headers/1]).

%%%===================================================================
%%% Decoding
%%%===================================================================

decode_challenge_headers(<<"Digest ", Challenge/binary>>) ->
  Fields = split_fields(Challenge),
  FieldMap = lists:foldl(fun decode_field/2, #{}, Fields),
  {ok, FieldMap};
decode_challenge_headers(_) ->
  {error, invalid_headers}.

split_fields(Challenge) ->
  string:split(Challenge, ", ", all). % TODO: Find a safer way to split the fields

decode_field(<<"realm=", Realm/binary>>, Acc) ->
  Acc#{realm => erldigest_utils:remove_surrounding_quotes(Realm)};
decode_field(<<"domain=", Domain/binary>>, Acc) ->
  Acc#{domain => erldigest_utils:remove_surrounding_quotes(Domain)};
decode_field(<<"nonce=", Nonce/binary>>, Acc) ->
  Acc#{nonce => erldigest_utils:remove_surrounding_quotes(Nonce)};
decode_field(<<"opaque=", Opaque/binary>>, Acc) ->
  Acc#{opaque => erldigest_utils:remove_surrounding_quotes(Opaque)};
decode_field(<<"stale=", Stale/binary>>, Acc) ->
  Acc#{stale => erldigest_utils:remove_surrounding_quotes(Stale)};
decode_field(<<"algorithm=", Algorithm/binary>>, Acc) ->
  Acc#{algorithm => erldigest_utils:remove_surrounding_quotes(Algorithm)};
decode_field(<<"qop=", Qop/binary>>, Acc) ->
  Acc#{qop => erldigest_utils:remove_surrounding_quotes(Qop)};
decode_field(<<"auth=", Auth/binary>>, Acc) ->
  Acc#{auth => erldigest_utils:remove_surrounding_quotes(Auth)}.

%%%===================================================================
%%% Encoding
%%%===================================================================

encode_response_headers(Options) ->
  Fields = encode_response_fields(Options),
  {ok, <<"Digest ", Fields/binary>>}.

encode_response_fields(Options) ->
  Fields = maps:fold(fun(Key, Value, Acc) ->
                       <<Acc/binary, (encode_response_field(Key, Value))/binary>>
                     end, <<>>, Options),
  binary:part(Fields, 0, byte_size(Fields)-2).

encode_response_field(username, Username) ->
  <<"username=\"", Username/binary, "\", ">>;
encode_response_field(realm, Realm) ->
  <<"realm=\"", Realm/binary, "\", ">>;
encode_response_field(nonce, Nonce) ->
  <<"nonce=\"", Nonce/binary, "\", ">>;
encode_response_field(uri, Uri) ->
  <<"uri=\"", Uri/binary, "\", ">>;
encode_response_field(response, Response) ->
  <<"response=\"", Response/binary, "\", ">>;
encode_response_field(algorithm, Algorithm) ->
  <<"algorithm=", Algorithm/binary, ", ">>;
encode_response_field(cnonce, CNonce) ->
  <<"cnonce=\"", CNonce/binary, "\", ">>;
encode_response_field(opaque, Opaque) ->
  <<"opaque=\"", Opaque/binary, "\", ">>;
encode_response_field(qop, Qop) ->
  <<"qop=", Qop/binary, ", ">>;
encode_response_field(nc, NonceCount) ->
  <<"nc=", NonceCount/binary, ", ">>;
encode_response_field(_, _) ->
  <<>>.

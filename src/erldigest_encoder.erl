-module(erldigest_encoder).

-export([decode_challenge_headers/1,
         encode_response_headers/1]).

%%%===================================================================
%%% Decoding
%%%===================================================================

decode_challenge_headers(<<"Digest ", Challenge/binary>>) ->
  Regex = <<"([^=]+)=(\"[^\"]*\")(?:\\s*,\\s*|\\s*$)">>,
  {match, Captures} = re:run(Challenge,  Regex, [global]),
  Fields = extract_fields(Captures, Challenge),
  {ok, Fields};
decode_challenge_headers(_) ->
  {error, invalid_headers}.

extract_fields(Captures, Challenge) ->
  extract_fields(Captures, Challenge, #{}).
extract_fields([Head | Tail], Challenge, Fields) ->
  [_, {KeyBegin, KeyLength}, {ValueBegin, ValueLength}] = Head,
  Key = get_atom_key(binary:part(Challenge, KeyBegin, KeyLength)),
  Value = erldigest_utils:remove_surrounding_quotes(binary:part(Challenge, ValueBegin, ValueLength)),
  extract_fields(Tail, Challenge, Fields#{Key => Value});
extract_fields([], _, Fields) ->
  Fields.

get_atom_key(BinaryKey) ->
  case BinaryKey of
    <<"realm">> -> realm;
    <<"domain">> -> domain;
    <<"nonce">> -> nonce;
    <<"opaque">> -> opaque;
    <<"stale">> -> stale;
    <<"algorithm">> -> algorithm;
    <<"qop">> -> qop
  end.

%%%===================================================================
%%% Encoding
%%%===================================================================

encode_response_headers(Options) ->
  Fields = encode_response_fields(Options),
  {ok, <<"Digest ", Fields/binary>>}.

encode_response_fields(Options) ->
  Keys = [username, realm, nonce, uri, response, algorithm, cnonce, opaque, qop, nc],
  Fields = lists:foldl(fun(Key, Acc) ->
                         BinaryKey = atom_to_binary(Key, latin1),
                         Value = maps:get(Key, Options, <<>>),
                         Field = encode_response_field(BinaryKey, Value),
                         <<Acc/binary, Field/binary>>
                       end, <<>>, Keys),
  binary:part(Fields, 0, byte_size(Fields)-1).

encode_response_field(_, <<>>) ->
  <<>>;
encode_response_field(<<"nc">>, NonceCount) ->
  <<"nc=", NonceCount/binary, ",">>;
encode_response_field(Key, Value) ->
  <<Key/binary, "=\"", Value/binary, "\",">>.

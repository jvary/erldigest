-module(erldigest_challenge).

-type challenge() :: #{atom() => binary()}.

-export([parse/1,
         make_challenge/1,
         get_value/2,
         get_value/3]).

-export_type([challenge/0]).

%%%===================================================================
%%% API
%%%===================================================================

-spec parse(Challenge::binary()) -> {ok, challenge()} | {error, Reason::atom()}.
parse(<<"Digest ", Challenge/binary>>) ->
  Regex = <<"([^=]+)=((?:[^\"]*)|(?:\"[^\"]*\"))(?:\\s*,\\s*|\\s*$)">>,
  case re:run(Challenge,  Regex, [global]) of
    {match, Captures} -> extract_fields(Captures, Challenge);
    nomatch -> {error, badarg}
  end;
parse(_) ->
  {error, badarg}.

-spec make_challenge(Challenge::challenge()) -> {ok, binary()} | {error, Reason::atom()}.
make_challenge(Challenge) when is_map(Challenge) ->
  Fields = make_challenge_fields(Challenge),
  {ok, <<"Digest ", Fields/binary>>};
make_challenge(_) ->
  {error, badarg}.

-spec get_value(Name::atom(), Challenge::binary() | map()) -> {ok, Value::binary()} | {error, Reason::atom()}.
get_value(Name, Challenge) when is_binary(Challenge) ->
  {ok, ParsedChallenge} = erldigest_challenge:parse(Challenge),
  maps:get(Name, ParsedChallenge);
get_value(Name, Challenge) when is_map(Challenge) ->
  maps:get(Name, Challenge);
get_value(_, _) ->
  {error, badarg}.

-spec get_value(Name::atom(), Challenge::binary() | map(), Default::binary()) -> {ok, Value::binary()} | {error, Reason::atom()}.
get_value(Name, Challenge, Default) ->
  try get_value(Name, Challenge) of
    Value -> Value
  catch
    error:{badkey, Name} -> Default
  end.

%%%===================================================================
%%% Internal Functions
%%%===================================================================

extract_fields(Captures, Challenge) ->
  try extract_fields(Captures, Challenge, #{}) of
    Fields -> {ok, Fields}
  catch
    error:Reason -> {error, Reason}
  end.
extract_fields([Head | Tail], Challenge, Fields) ->
  [_, {KeyBegin, KeyLength}, {ValueBegin, ValueLength}] = Head,
  Key = get_field_name_atom(binary:part(Challenge, KeyBegin, KeyLength)),
  Value = erldigest_utils:remove_surrounding_quotes(binary:part(Challenge, ValueBegin, ValueLength)),
  extract_fields(Tail, Challenge, Fields#{Key => Value});
extract_fields([], _, Fields) ->
  Fields.

get_field_name_atom(BinaryKey) ->
  case BinaryKey of
    <<"realm">> -> realm;
    <<"domain">> -> domain;
    <<"nonce">> -> nonce;
    <<"opaque">> -> opaque;
    <<"stale">> -> stale;
    <<"algorithm">> -> algorithm;
    <<"qop">> -> qop;
    <<"username">> -> username;
    <<"uri">> -> uri;
    <<"response">> -> response;
    <<"cnonce">> -> cnonce;
    <<"nc">> -> nc
  end.

make_challenge_fields(Options) ->
  Keys = [username, realm, nonce, uri, response, algorithm, cnonce, opaque, qop, nc],
  Fields = lists:foldl(fun(Key, Acc) ->
                         BinaryKey = atom_to_binary(Key, latin1),
                         Value = maps:get(Key, Options, <<>>),
                         Field = make_challenge_field(BinaryKey, Value),
                         <<Acc/binary, Field/binary>>
                       end, <<>>, Keys),
  binary:part(Fields, 0, byte_size(Fields)-1).

make_challenge_field(_, <<>>) ->
  <<>>;
make_challenge_field(<<"nc">>, NonceCount) ->
  <<"nc=", NonceCount/binary, ",">>;
make_challenge_field(Key, Value) ->
  <<Key/binary, "=\"", Value/binary, "\",">>.

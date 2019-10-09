-module(erldigest).

-export([calculate_response/5,
         validate_response/5,
         generate_challenge/2,
         challenge_to_binary/1,
         get_A1_hash/3,
         get_A1_hash/4]).

-type method() :: atom() | binary() | string().
-type qop() :: none | auth | auth_int | both.
-type algorithm() :: md5 | sha256.
-type challenge() :: erldigest_challenge:challenge().

-export_type([challenge/0]).

%%%===================================================================
%%% API
%%%===================================================================

-spec calculate_response(Method, Uri, Headers, Username, Password) -> Result when
  Method :: method(),
  Uri :: binary(),
  Headers :: #{binary() => binary()},
  Username :: binary(),
  Password :: binary(),
  Result :: {ok, challenge()} | {error, Reason::term()}.
calculate_response(Method, Uri, Headers, Username, Password) ->
  {ok, Options} = erldigest_challenge:parse(Headers),
  NewOptions = Options#{username => Username,
                        password => Password,
                        method => erldigest_utils:method_to_binary(Method),
                        uri => Uri},
  Algorithm = erldigest_utils:get_digest_algorithm(Options),
  Response = calculate_request_digest(NewOptions, Algorithm),
  erldigest_challenge:make_challenge(Response).

-spec validate_response(Method, Uri, ClientResponse, ServerResponse, HA1) -> Result when
  Method :: method(),
  Uri :: binary(),
  ClientResponse :: binary(),
  ServerResponse :: binary() | challenge(),
  HA1 :: binary(),
  Result :: {ok, boolean()} | {error, Reason::term()}.
validate_response(Method, Uri, ClientResponse, <<ServerResponse/binary>>, HA1) ->
  {ok, Challenge} = erldigest_challenge:parse(ServerResponse),
  #{qop := EntryServerQop} = Challenge,
  NewChallenge = Challenge#{qop => binary:replace(EntryServerQop, <<" ">>, <<>>, [global])},
  validate_response(Method, Uri, ClientResponse, NewChallenge, HA1);

validate_response(Method, Uri, ClientResponse, ServerResponse, HA1) when is_map(ServerResponse)->
  {ok, Response} = erldigest_challenge:parse(ClientResponse),
  Result = get_solvable_challenge(Response, ServerResponse#{ha1 => HA1,
                                                            method => erldigest_utils:method_to_binary(Method),
                                                            uri => Uri}),
  case Result of
    {ok, SolvableChallenge} ->
      Algorithm = erldigest_utils:get_digest_algorithm(SolvableChallenge),
      RealResponse = calculate_response_digest(SolvableChallenge, Algorithm),
      AreResponseEquals = maps:get(response, RealResponse) == maps:get(response, Response),
      {ok, AreResponseEquals};
    {error, _Error} = Error ->
      Error
  end.

-spec generate_challenge(Realm, Qop) -> Result when
  Realm :: binary(),
  Qop :: qop(),
  Result :: {ok, Challenge :: challenge()} | {error, Reason::term()}.
generate_challenge(Realm, Qop) ->
  {_Nc, Nonce} = erldigest_nonce_generator:generate(),
  Challenge = #{realm => Realm, nonce => Nonce, qop => get_challenge_qop(Qop)},
  {ok, Challenge}.

-spec challenge_to_binary(Challenge) -> Result when
  Challenge :: challenge(),
  Result :: {ok, binary()} | {error, Reason::term()}.
challenge_to_binary(#{qop := Qop, realm := Realm, nonce := Nonce} = _Challenge) ->
  RealmLine = get_realm_line(Realm),
  NonceLine = get_nonce_line(Nonce),
  QopLine = get_qop_line(Qop),
  ChallengeBin = <<"Digest ", RealmLine/binary,
                              NonceLine/binary,
                              QopLine/binary>>,
  {ok, binary:part(ChallengeBin, 0, byte_size(ChallengeBin)-1)}.

-spec get_A1_hash(Username, Realm, Password) -> Result when
  Username :: binary(),
  Realm :: binary(),
  Password :: binary(),
  Result :: binary().
get_A1_hash(Username, Realm, Password) ->
  get_A1_hash(#{username => Username, realm => Realm, password => Password}, md5).

-spec get_A1_hash(Username, Realm, Password, Algorithm) -> Result when
  Username :: binary(),
  Realm :: binary(),
  Password :: binary(),
  Algorithm :: algorithm(),
  Result :: binary().
get_A1_hash(Username, Realm, Password, Algorithm)->
  get_A1_hash(#{username => Username, realm => Realm, password => Password}, Algorithm).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

calculate_request_digest(#{qop := Qop, nonce := Nonce} = Options, Algorithm) ->
  HA1 = get_A1_hash(Options, Algorithm),
  HA2 = get_A2_hash(Options, Algorithm),
  {NonceCount, CNonce} = erldigest_nonce_generator:generate(),
  NewQop = get_qop(Qop),
  Digest = hex_digest(<<HA1/binary, ":", Nonce/binary, ":", NonceCount/binary, ":", CNonce/binary, ":", NewQop/binary, ":", HA2/binary>>, Algorithm),
  Options#{nc => NonceCount, cnonce => CNonce, response => Digest};
calculate_request_digest(#{nonce := Nonce} = Options, Algorithm) ->
  HA1 = get_A1_hash(Options, Algorithm),
  HA2 = get_A2_hash(Options, Algorithm),
  Digest = hex_digest(<<HA1/binary, ":", Nonce/binary, ":", HA2/binary>>, Algorithm),
  Options#{response => Digest}.

calculate_response_digest(#{qop := Qop, nonce := Nonce, nc := NonceCount, cnonce := CNonce, ha1 := HA1} = Options, Algorithm) ->
  HA2 = get_A2_hash(Options, Algorithm),
  Digest = hex_digest(<<HA1/binary, ":", Nonce/binary, ":", NonceCount/binary, ":", CNonce/binary, ":", Qop/binary, ":", HA2/binary>>, Algorithm),
  Options#{nc => NonceCount, cnonce => CNonce, response => Digest};
calculate_response_digest(#{nonce := Nonce, ha1 := HA1} = Options, Algorithm) ->
  HA2 = get_A2_hash(Options, Algorithm),
  Digest = hex_digest(<<HA1/binary, ":", Nonce/binary, ":", HA2/binary>>, Algorithm),
  Options#{response => Digest}.

get_A1_hash(#{algorithm := <<"MD5-sess">>, realm := Realm, nonce := Nonce, cnonce := CNonce, username := Username, password := Password}, Algorithm) ->
  InnerA1 = <<Username/binary, ":", Realm/binary, ":", Password/binary>>,
  A1 = <<(hex_digest(InnerA1, Algorithm))/binary, ":", Nonce/binary, ":", CNonce/binary>>,
  hex_digest(A1, Algorithm);
get_A1_hash(#{algorithm := <<"MD5">>, realm := Realm, username := Username, password := Password}, Algorithm) ->
  A1 = <<Username/binary, ":", Realm/binary, ":", Password/binary>>,
  hex_digest(A1, Algorithm);
get_A1_hash(#{realm := Realm, username := Username, password := Password}, Algorithm) ->
  A1 = <<Username/binary, ":", Realm/binary, ":", Password/binary>>,
  hex_digest(A1, Algorithm).

get_A2_hash(#{qop := <<"auth-int">>, method := Method, uri := Uri, body := Body}, Algorithm) ->
  A2 = <<Method/binary, ":", Uri/binary, ":", Body/binary>>,
  hex_digest(A2, Algorithm);
get_A2_hash(#{qop := <<"auth,auth-int">>, method := Method, uri := Uri}, Algorithm) ->
  A2 = <<Method/binary, ":", Uri/binary>>,
  hex_digest(A2, Algorithm);
get_A2_hash(#{qop := <<"auth">>, method := Method, uri := Uri}, Algorithm) ->
  A2 = <<Method/binary, ":", Uri/binary>>,
  hex_digest(A2, Algorithm);
get_A2_hash(#{method := Method, uri := Uri}, Algorithm) ->
  A2 = <<Method/binary, ":", Uri/binary>>,
  hex_digest(A2, Algorithm).

hex_digest(Data, Algorithm) ->
  erldigest_binutils:binary_to_hex(crypto:hash(Algorithm, Data)).

get_qop(Qop) ->
  case Qop of
    <<"auth,auth-int">> -> <<"auth">>; %TODO: Choose wisely
    Qop -> Qop
  end.

get_server_possible_qop(<<>>) -> [<<>>];
get_server_possible_qop(<<"auth">>) -> [<<>>, <<"auth">>];
get_server_possible_qop(<<"auth-int">>) -> [<<>>, <<"auth-int">>];
get_server_possible_qop(<<"auth,auth-int">>) -> [<<>>, <<"auth">>, <<"auth-int">>].

get_solvable_challenge(Response, Challenge) ->
  ServerQop = maps:get(qop, Challenge, <<>>),
  ClientQop = maps:get(qop, Response, <<>>),
  case lists:member(ClientQop, get_server_possible_qop(ServerQop)) of
    false -> {error, bad_qop};
    true -> try_merge_response_and_challenge(Response, maps:without([qop], Challenge))
  end.

try_merge_response_and_challenge(Response, Challenge) ->
  try maps:merge(Response, Challenge) of
    SolvableChallenge -> {ok, SolvableChallenge}
  catch
    error:Reason -> {error, Reason}
  end.

get_realm_line(Realm) ->
  <<"realm=\"", Realm/binary, "\",">>.

get_nonce_line(Nonce) ->
  <<"nonce=\"", Nonce/binary, "\",">>.

get_qop_line(Qop) ->
  <<"qop=\"", Qop/binary, "\",">>.

-spec get_challenge_qop(qop()) -> binary().
get_challenge_qop(Qop) ->
  case Qop of
    none -> <<>>;
    auth -> <<"auth">>;
    auth_int -> <<"auth-int">>;
    both -> <<"auth,auth-int">>
  end.
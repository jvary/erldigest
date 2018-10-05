-module(erldigest).

-export([calculate_response/5,
         validate_response/5]).

calculate_response(Method, Uri, Headers, Username, Password) ->
  {ok, Options} = erldigest_challenge:parse(Headers),
  NewOptions = Options#{username => Username,
                        password => Password,
                        method => method_to_binary(Method),
                        uri => Uri},
  Algorithm = erldigest_utils:get_digest_algorithm(Options),
  Response = calculate_request_digest(NewOptions, Algorithm),
  erldigest_challenge:make_challenge(Response).

validate_response(Method, Uri, ClientResponse, ServerResponse, HA1) ->
  {ok, Challenge} = erldigest_challenge:parse(ServerResponse),
  {ok, Response} = erldigest_challenge:parse(ClientResponse),
  Result = get_solvable_challenge(Response, Challenge#{ha1 => HA1,
                                                         method => method_to_binary(Method),
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

method_to_binary(Method) ->
  list_to_binary(string:uppercase(io_lib:format("~s", [Method]))).

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
  erldigest_utils:binary_to_hex(crypto:hash(Algorithm, Data)).

get_qop(Qop) ->
  case Qop of
    <<"auth,auth-int">> -> <<"auth">>;
    Qop -> Qop
  end.

get_solvable_challenge(Response, Challenge) ->
  ServerQop = maps:get(qop, Challenge, <<>>),
  ClientQop = maps:get(qop, Response, <<>>),
  PossibleServerQop = binary:split(binary:replace(ServerQop, <<" ">>, <<>>, [global]), <<",">>),
  case lists:member(ClientQop, PossibleServerQop) of
    false -> {error, bad_qop};
    true -> try_merge_response_and_challenge(Response, maps:without([qop], Challenge))
  end.

try_merge_response_and_challenge(Response, Challenge) ->
  try maps:merge(Response, Challenge) of
    SolvableChallenge -> {ok, SolvableChallenge}
  catch
    error:Reason -> {error, Reason}
  end.

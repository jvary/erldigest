-module(erldigest).

-export([calculate_response/5]).

calculate_response(Method, Uri, Headers, Username, Password) ->
  {ok, Options} = erldigest_parser:parse_challenge_headers(Headers),
  {NonceCount, CNonce} = erldigest_nonce_generator:generate_nonce(),
  NewOptions = Options#{username => Username,
                        password => Password,
                        method => Method,
                        uri => Uri,
                        nc => NonceCount,
                        cnonce => CNonce},
  Algorithm = erldigest_utils:get_digest_algorithm(Options),
  Digest = calculate_request_digest(NewOptions, Algorithm),
  erldigest_encoder:encode_response_headers(NewOptions#{response => Digest}).

calculate_request_digest(#{qop := _, nonce := Nonce, nc := NonceCount, cnonce := CNonce, qop := Qop} = Options, Algorithm) ->
  HA1 = get_A1_hash(Options, Algorithm),
  HA2 = get_A2_hash(Options, Algorithm),
  hex_digest(<<HA1/binary, ":", Nonce/binary, ":", NonceCount/binary, ":", CNonce/binary, ":", Qop/binary, ":", HA2/binary>>, Algorithm);
calculate_request_digest(#{nonce := Nonce} = Options, Algorithm) ->
  HA1 = get_A1_hash(Options, Algorithm),
  HA2 = get_A2_hash(Options, Algorithm),
  hex_digest(<<HA1/binary, Nonce/binary, ":", HA2/binary>>, Algorithm).

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
get_A2_hash(#{qop := <<"auth">>, method := Method, uri := Uri}, Algorithm) ->
  A2 = <<Method/binary, ":", Uri/binary>>,
  hex_digest(A2, Algorithm);
get_A2_hash(#{method := Method, uri := Uri}, Algorithm) ->
  A2 = <<Method/binary, ":", Uri/binary>>,
  hex_digest(A2, Algorithm).

hex_digest(Data, Algorithm) ->
  erldigest_utils:binary_to_hex(crypto:hash(Algorithm, Data)).

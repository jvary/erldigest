-module(erldigest).

-export([calculate_response/5]).

calculate_response(Method, Uri, Headers, Username, Password) ->
  {ok, Options} = erldigest_encoder:decode_challenge_headers(Headers),
  NewOptions = Options#{username => Username,
                        password => Password,
                        method => method_to_binary(Method),
                        uri => Uri},
  Algorithm = erldigest_utils:get_digest_algorithm(Options),
  Response = calculate_request_digest(NewOptions, Algorithm),
  erldigest_encoder:encode_response_headers(Response).

method_to_binary(Method) ->
  list_to_binary(string:uppercase(io_lib:format("~s", [Method]))).

calculate_request_digest(#{qop := Qop, nonce := Nonce} = Options, Algorithm) ->
  HA1 = get_A1_hash(Options, Algorithm),
  HA2 = get_A2_hash(Options, Algorithm),
  {NonceCount, CNonce} = erldigest_nonce_generator:generate(),
  NewQop =
    case Qop of
      <<"auth,auth-int">> -> <<"auth">>;
      Qop -> Qop
    end,
  Digest = hex_digest(<<HA1/binary, ":", Nonce/binary, ":", NonceCount/binary, ":", CNonce/binary, ":", NewQop/binary, ":", HA2/binary>>, Algorithm),
  Options#{nc => NonceCount, cnonce => CNonce, response => Digest};
calculate_request_digest(#{nonce := Nonce} = Options, Algorithm) ->
  HA1 = get_A1_hash(Options, Algorithm),
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

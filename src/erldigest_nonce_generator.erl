-module(erldigest_nonce_generator).

-export([generate/0]).

generate() ->
  NC = pad_left(integer_to_binary(erlang:unique_integer([positive, monotonic])), 8, $0),
  Nonce = base64:encode(crypto:strong_rand_bytes(30)),
  {NC, Nonce}.

pad_left(Binary, DesiredLength, PaddingChar) ->
  case byte_size(Binary) of
    DesiredLength ->
      Binary;
    Length when Length < DesiredLength ->
      pad_left(<<PaddingChar, Binary/binary>>, DesiredLength, PaddingChar)
  end.

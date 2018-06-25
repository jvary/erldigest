-module(erldigest_utils).

-export([binary_to_hex/1,
         remove_surrounding_quotes/1,
         get_digest_algorithm/1]).

binary_to_hex(Binary) ->
  binary_to_hex(Binary, <<>>).
binary_to_hex(<<X:8/integer, Rest/binary>>, Acc) ->
  Hex = string:lowercase(byte_to_hex(X)),
  binary_to_hex(Rest, <<Acc/binary, Hex/binary>>);
binary_to_hex(<<>>, Acc) ->
  Acc.

byte_to_hex(X) when X band 16#f0 > 0 ->
  integer_to_binary(X, 16);
byte_to_hex(X) ->
  <<"0", (integer_to_binary(X, 16))/binary>>.

remove_surrounding_quotes(Str) ->
  remove_surrounding_quotes(Str, false).
remove_surrounding_quotes(<<"\"", Str/binary>>, false) ->
  remove_surrounding_quotes(Str, true);
remove_surrounding_quotes(Str, true) ->
  Length = byte_size(Str) - 1,
  <<UnquotedStr:Length/binary, "\"">> = Str,
  UnquotedStr;
remove_surrounding_quotes(Str, false) ->
  Str.

get_digest_algorithm(<<"MD5", _/binary>>) ->
  md5;
get_digest_algorithm(<<"SHA-256", _/binary>>) ->
  sha256;
get_digest_algorithm(_) ->
  md5.

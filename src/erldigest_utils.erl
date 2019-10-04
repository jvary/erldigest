-module(erldigest_utils).

-export([remove_surrounding_quotes/1,
         get_digest_algorithm/1]).

remove_surrounding_quotes(<<Str/binary>>) ->
  remove_surrounding_quotes(Str, false).
remove_surrounding_quotes(<<"\"", Str/binary>>, false) ->
  remove_surrounding_quotes(Str, true);
remove_surrounding_quotes(Str, true) ->
  Length = byte_size(Str) - 1,
  <<UnquotedStr:Length/binary, "\"">> = Str,
  UnquotedStr;
remove_surrounding_quotes(Str, false) ->
  Str.

get_digest_algorithm(#{algorithm := <<"MD5", _/binary>>}) ->
  md5;
get_digest_algorithm(#{algorithm := <<"SHA-256", _/binary>>}) ->
  sha256;
get_digest_algorithm(_) ->
  md5.

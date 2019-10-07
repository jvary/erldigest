-module(erldigest_utils).

-export([
  remove_surrounding_quotes/1,
  get_digest_algorithm/1,
  method_to_binary/1
]).

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

method_to_binary(<<Binary/binary>>) ->
  case Binary of
    <<"GET">> -> <<"GET">>;
    <<"POST">> -> <<"POST">>;
    <<"PUT">> -> <<"PUT">>;
    <<"DELETE">> -> <<"DELETE">>;
    <<"OPTIONS">> -> <<"OPTIONS">>;
    <<"HEAD">> -> <<"HEAD">>;
    <<"CONNECT">> -> <<"CONNECT">>;
    <<"DESCRIBE">> -> <<"DESCRIBE">>;
    <<"SETUP">> -> <<"SETUP">>;
    <<"PLAY">> -> <<"PLAY">>;
    <<"PAUSE">> -> <<"PAUSE">>;
    <<"RECORD">> -> <<"RECORD">>;
    <<"ANNOUNCE">> -> <<"ANNOUNCE">>;
    <<"TEARDOWN">> -> <<"TEARDOWN">>;
    <<"GET_PARAMETER">> -> <<"GET_PARAMETER">>;
    <<"SET_PARAMETER">> -> <<"SET_PARAMETER">>;
    <<"REDIRECT">> -> <<"REDIRECT">>;
    _ -> string:uppercase(Binary)
  end;
method_to_binary(Atom) when is_atom(Atom) ->
  case Atom of
    get -> <<"GET">>;
    post -> <<"POST">>;
    put -> <<"PUT">>;
    delete -> <<"DELETE">>;
    options -> <<"OPTIONS">>;
    head -> <<"HEAD">>;
    connect -> <<"CONNECT">>;
    describe -> <<"DESCRIBE">>;
    setup -> <<"SETUP">>;
    play -> <<"PLAY">>;
    pause -> <<"PAUSE">>;
    record -> <<"RECORD">>;
    announce -> <<"ANNOUNCE">>;
    teardown -> <<"TEARDOWN">>;
    get_parameter -> <<"GET_PARAMETER">>;
    set_parameter -> <<"SET_PARAMETER">>;
    redirect -> <<"REDIRECT">>;
    _ -> string:uppercase(erlang:atom_to_binary(Atom, latin1))
  end;
method_to_binary(Method) ->
  list_to_binary(string:uppercase(io_lib:format("~s", [Method]))).
-module(erldigest_nonce_generator).

-export([generate/0]).

generate() ->
  {<<"00000001">>, <<"0a4f113b">>}. % TODO: Really generate nonce
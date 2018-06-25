-module(erldigest_nonce_generator).

-export([generate_nonce/0]).

generate_nonce() ->
  {<<"00000001">>, <<"0a4f113b">>}. % TODO: Really generate nonce
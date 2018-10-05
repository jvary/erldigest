-module(erldigest_challenge_tests).
-include_lib("eunit/include/eunit.hrl").

setup() ->
  ok.

decode_simple_challenge_test() ->
  Challenge = <<"Digest realm=\"http-auth@example.org\", ",
                        "domain=\"http://www.ietf.org/rfc/rfc2617\", ",
                        "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", ",
                        "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\", ",
                        "algorithm=\"SHA256\", ",
                        "qop=\"auth,auth-int\"">>,
  {ok, Result} = erldigest_challenge:parse(Challenge),
  Expected = #{realm => <<"http-auth@example.org">>,
              domain => <<"http://www.ietf.org/rfc/rfc2617">>,
              nonce => <<"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v">>,
              opaque => <<"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS">>,
              algorithm => <<"SHA256">>,
              qop => <<"auth,auth-int">>},
  ?assertEqual(Expected, Result).
% TODO: Add a test for : qop="auth, auth-int" (SPACE)

encode_challenge_response_test() ->
  Response = #{username => <<"Mufasa">>,
               realm => <<"testrealm@host.com">>,
               nonce => <<"dcd98b7102dd2f0e8b11d0f600bfb0c093">>,
               uri => <<"/dir/index.html">>,
               response => <<"6629fae49393a05397450978507c4ef1">>,
               algorithm => <<"SHA256">>,
               cnonce => <<"0a4f113b">>,
               opaque => <<"5ccc069c403ebaf9f0171e9517f40e41">>,
               qop => <<"auth">>,
               nc => <<"00000001">>},
  {ok, Result} = erldigest_challenge:make_challenge(Response),
  Expected = <<"Digest username=\"Mufasa\",",
                      "realm=\"testrealm@host.com\",",
                      "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",",
                      "uri=\"/dir/index.html\",",
                      "response=\"6629fae49393a05397450978507c4ef1\",",
                      "algorithm=\"SHA256\",",
                      "cnonce=\"0a4f113b\",",
                      "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\",",
                      "qop=\"auth\",",
                      "nc=00000001">>,
  erldigest_test_utils:assert_response_are_equivalent(Expected, Result).

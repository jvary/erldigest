-module(erldigest_tests).
-include_lib("eunit/include/eunit.hrl").

rfc_2617_example_test() ->
  meck:new(erldigest_nonce_generator, [passthrough, unstick, nolink]),
  meck:expect(erldigest_nonce_generator, generate_nonce, 0, {<<"00000001">>, <<"0a4f113b">>}),
  Challenge = <<"Digest realm=\"testrealm@host.com\", ",
                        "qop=\"auth,auth-int\", ",
                        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", ",
                        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>,
  {ok, Response} = erldigest:calculate_response(<<"GET">>, <<"/dir/index.html">>, Challenge, <<"Mufasa">>, <<"Circle Of Life">>),
  Expected = <<"Digest username=\"Mufasa\", ",
                        "realm=\"testrealm@host.com\", ",
                        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", ",
                        "uri=\"/dir/index.html\", ",
                        "response=\"6629fae49393a05397450978507c4ef1\", ",
                        "cnonce=\"0a4f113b\", ",
                        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", ",
                        "qop=auth, ",
                        "nc=00000001">>,
  meck:unload(erldigest_nonce_generator),
  erldigest_test_utils:assert_response_are_equivalent(Expected, Response).

another_example_test() ->
  meck:new(erldigest_nonce_generator, [passthrough, unstick, nolink]),
  meck:expect(erldigest_nonce_generator, generate_nonce, 0, {<<"00000001">>, <<"61417766e50cb980">>}),
  Challenge = <<"Digest realm=\"test.dev\", ",
                        "qop=\"auth\", ",
                        "nonce=\"064af982c5b571cea6450d8eda91c20d\", ",
                        "opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\"">>,
  {ok, Response} = erldigest:calculate_response(<<"GET">>, <<"/login">>, Challenge, <<"user.name">>, <<"s3cr3tP@ssw0rd">>),
  Expected = <<"Digest username=\"user.name\", ",
                        "realm=\"test.dev\", ",
                        "nonce=\"064af982c5b571cea6450d8eda91c20d\", ",
                        "uri=\"/login\", ",
                        "response=\"70eda34f1683041fd9ab72056c51b740\", ",
                        "cnonce=\"61417766e50cb980\", ",
                        "opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\", ",
                        "qop=auth, ",
                        "nc=00000001">>,
  meck:unload(erldigest_nonce_generator),
  erldigest_test_utils:assert_response_are_equivalent(Expected, Response).

httpbin_MD5_test() ->
  application:ensure_all_started(hackney),
  Username = <<"SuperUser">>,
  Password = <<"DuperPassword">>,
  Url = <<"/digest-auth/auth/", Username/binary, "/", Password/binary>>,
  FullUrl = <<"https://httpbin.org", Url/binary>>,
  {ok, 401, RespHeaders, ClientRef} =  hackney:request(get, FullUrl),
  {ok, _} = hackney:body(ClientRef),
  Challenge = proplists:get_value(<<"Www-Authenticate">>, RespHeaders),
  {ok, ChallengeResponse} = erldigest:calculate_response(<<"GET">>, Url, Challenge, Username, Password),
  Headers = [{<<"Authorization">>, ChallengeResponse}],
  {ok, StatusCode, _, ClientRef2} =  hackney:request(get, FullUrl, Headers),
  {ok, _} = hackney:body(ClientRef2),
  ?assertEqual(200, StatusCode).

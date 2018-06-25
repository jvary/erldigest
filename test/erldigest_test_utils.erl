-module(erldigest_test_utils).
-include_lib("eunit/include/eunit.hrl").

-export([assert_response_are_equivalent/2]).

assert_response_are_equivalent(Expected, Response) ->
  NewExpected = response_to_list(Expected),
  NewResponse = response_to_list(Response),
  io:format("~nExpected: ~p~nGot     : ~p~n", [NewExpected, NewResponse]),
  ?assertMatch(NewExpected, NewResponse).

response_to_list(Response) ->
  List = 
    lists:foldl(fun(Element, Acc) ->
                  NewElement =
                    case binary:last(Element) of
                      $, -> binary:part(Element, {0, byte_size(Element) - 1});
                      _ -> Element
                    end,
                  [NewElement | Acc]
                end, [], binary:split(Response, <<" ">>, [global])),
  lists:sort(List).
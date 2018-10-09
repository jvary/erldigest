-module(erldigest_test_utils).
-include_lib("eunit/include/eunit.hrl").

-export([assert_response_are_equivalent/2]).

assert_response_are_equivalent(Expected, Response) ->
  NewExpected = response_to_list(Expected),
  NewResponse = response_to_list(Response),
  io:format("~nExpected: ~p~nGot     : ~p~n", [NewExpected, NewResponse]),
  ?assertMatch(NewExpected, NewResponse).

response_to_list(Response) ->
  Regex = <<"((?:[^=]+)=(?:\"?[^\"]*\"?)(?:\\s*,\\s*|\\s*$))">>,
  {match, Captures} = re:run(Response,  Regex, [global]),
  Fields = extract_fields(Captures, Response),
  List = 
    lists:foldl(fun(Element, Acc) ->
                  NewElement =
                    case binary:last(Element) of
                      $, -> binary:part(Element, {0, byte_size(Element) - 1});
                      _ -> Element
                    end,
                  [NewElement | Acc]
                end, [], Fields),
  lists:sort(List).

extract_fields(Captures, Challenge) ->
  extract_fields(Captures, Challenge, []).
extract_fields([Head | Tail], Challenge, Fields) ->
  [_, {Begin, Length}] = Head,
  Field = binary:part(Challenge, Begin, Length),
  extract_fields(Tail, Challenge, [Field | Fields]);
extract_fields([], _, Fields) ->
  Fields.

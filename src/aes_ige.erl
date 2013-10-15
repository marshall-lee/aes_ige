-module(aes_ige).

-export([crypt/4, encrypt/3, decrypt/3]).
-export([bi_crypt/5, bi_encrypt/4, bi_decrypt/4]).

-on_load(init/0).

-define(nif_stub, nif_stub_error(?LINE)).
nif_stub_error(Line) ->
    erlang:nif_error({nif_not_loaded,module,?MODULE,line,Line}).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

init() ->
    PrivDir = case code:priv_dir(?MODULE) of
                  {error, bad_name} ->
                      EbinDir = filename:dirname(code:which(?MODULE)),
                      AppPath = filename:dirname(EbinDir),
                      filename:join(AppPath, "priv");
                  Path ->
                      Path
              end,
    erlang:load_nif(filename:join(PrivDir, ?MODULE), 0).

crypt(_Key, _IVec, _Data, _IsEncrypt) -> ?nif_stub.
encrypt(Key, IVec, Data) -> crypt(Key, IVec, Data, true).
decrypt(Key, IVec, Data) -> crypt(Key, IVec, Data, false).

bi_crypt(_Key1, _Key2, _IVec, _Data, _IsEncrypt) -> ?nif_stub.
bi_encrypt(Key1, Key2, IVec, Data) -> bi_crypt(Key1, Key2, IVec, Data, true).
bi_decrypt(Key1, Key2, IVec, Data) -> bi_crypt(Key1, Key2, IVec, Data, false).

%% ===================================================================
%% EUnit tests
%% ===================================================================
-ifdef(TEST).

simple(Key, IVec, Data) ->
    E = encrypt(Key, IVec, Data),
    ?assertEqual(byte_size(E), byte_size(Data)),
    ?assertNotEqual(E, Data),
    D = decrypt(Key, IVec, E),
    ?assertEqual(byte_size(D), byte_size(E)),
    ?assertEqual(Data, D).

bi_simple(Key1, Key2, IVec, Data) ->
    E = bi_encrypt(Key1, Key2, IVec, Data),
    ?assertEqual(byte_size(E), byte_size(Data)),
    ?assertNotEqual(E, Data),
    D = bi_decrypt(Key1, Key2, IVec, E),
    ?assertEqual(byte_size(D), byte_size(E)),
    ?assertEqual(Data, D).

full(Key, IVec, Plaintext, Ciphertext) ->
    Ciphertext_ = encrypt(Key, IVec, Plaintext),
    ?assertEqual(Ciphertext_, Ciphertext),
    Plaintext_ = decrypt(Key, IVec, Ciphertext),
    ?assertEqual(Plaintext_, Plaintext).

bi_full(Key1, Key2, IVec, Plaintext, Ciphertext) ->
    Ciphertext_ = bi_encrypt(Key1, Key2, IVec, Plaintext),
    ?assertEqual(Ciphertext_, Ciphertext),
    Plaintext_ = bi_decrypt(Key1, Key2, IVec, Ciphertext),
    ?assertEqual(Plaintext_, Plaintext).

random128_test() ->
    IV = crypto:rand_bytes(32),
    Key = crypto:rand_bytes(16),
    Datas = [ crypto:rand_bytes(I*16) || I <- lists:seq(1,8) ],
    lists:foreach(fun(Data) -> simple(Key, IV, Data) end, Datas).

random256_test() ->
    IV = crypto:rand_bytes(32),
    Key = crypto:rand_bytes(32),
    Datas = [ crypto:rand_bytes(I*16) || I <- lists:seq(1,8) ],
    lists:foreach(fun(Data) -> simple(Key, IV, Data) end, Datas).

bi_random128_test() ->
    IV = crypto:rand_bytes(64),
    Key2 = crypto:rand_bytes(16),
    Key1 = crypto:rand_bytes(16),
    Datas = [ crypto:rand_bytes(I*16) || I <- lists:seq(1,8) ],
    lists:foreach(fun(Data) -> bi_simple(Key1, Key2, IV, Data) end, Datas).

bi_random256_test() ->
    IV = crypto:rand_bytes(64),
    Key1 = crypto:rand_bytes(32),
    Key2 = crypto:rand_bytes(32),
    Datas = [ crypto:rand_bytes(I*16) || I <- lists:seq(1,8) ],
    lists:foreach(fun(Data) -> bi_simple(Key1, Key2, IV, Data) end, Datas).

first_test() ->
    Key = binary:list_to_bin(lists:seq(0,15)),
    IVec = binary:list_to_bin(lists:seq(0,31)),
    Plaintext = binary:list_to_bin(lists:duplicate(32,0)),
    Ciphertext = <<16#1A8519A6:32, 16#557BE652:32, 16#E9DA8E43:32, 16#DA4EF445:32,
                   16#3CF456B4:32, 16#CA488AA3:32, 16#83C79C98:32, 16#B34797CB:32>>,
    full(Key, IVec, Plaintext, Ciphertext).

bi_first_test() ->
    Key1 = binary:list_to_bin(lists:seq(0,15)),
    Key2 = binary:list_to_bin(lists:seq(16,31)),
    IVec = binary:list_to_bin(lists:seq(0,63)),
    Plaintext = binary:list_to_bin(lists:duplicate(32,0)),
    Ciphertext = <<16#14406FAE:32, 16#A279F256:32, 16#1F86EB3B:32, 16#7DFF53DC:32,
                   16#4E270C03:32, 16#DE7CE516:32, 16#6A9C2033:32, 16#9D33FE12:32>>,
    bi_full(Key1, Key2, IVec, Plaintext, Ciphertext).
-endif.

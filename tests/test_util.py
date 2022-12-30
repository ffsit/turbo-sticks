import pytest
from time import time, sleep

import turbo_sticks.util as util
from turbo_sticks.config import patch_config


def test_generate_random_token():
    token = util.generate_random_token(16)
    assert len(token) == 16
    assert len(bytes.fromhex(token)) == 8
    assert token != util.generate_random_token(16)


def test_encryption():
    cleartext = 'test'
    ciphertext = util.encrypt(cleartext)
    assert len(ciphertext) == 40
    assert util.encrypt(cleartext) != ciphertext
    assert util.decrypt(ciphertext) == cleartext
    with patch_config(app_secret='different_key_from_before'):
        assert util.decrypt(ciphertext) != cleartext


def test_sub_title():
    assert util.sub_title('Test') == 'Test - TURBO Sticks'
    assert util.sub_title('Test', 'Page Title') == 'Test - Page Title'


def test_basic_response_header():
    headers = util.basic_response_header(b'body')
    assert len(headers) == 2
    assert headers[0] == ('Content-Type', 'text/html')
    assert headers[1] == ('Content-Length', '4')


def test_basic_response_header_no_content_length():
    headers = util.basic_response_header(b'body', send_length=False)
    assert len(headers) == 1
    assert headers[0] == ('Content-Type', 'text/html')


def test_generate_json_response():
    data = {'errors': []}
    body, headers, status = util.generate_json_response(data)
    assert body == b'{"errors": []}'
    assert len(headers) == 2
    assert headers[0] == ('Content-Type', 'application/json')
    assert headers[1] == ('Content-Length', '14')


def test_get_default_embed():
    assert util.get_default_embed([]) == ''
    assert util.get_default_embed([{'embed_type': 'other'}]) == ''
    assert util.get_default_embed(
        [{'embed_type': 'html', 'embed': 'test'}]
    ) == 'test'


def test_build_url():
    assert util.build_url('/') == 'https://example.com/'
    assert util.build_url('/', base='base') == 'https://example.com/'
    assert util.build_url('/', base='api') == 'https://example.com/api/'
    assert util.build_url('/', base='websockets') == (
        'wss://example.com/websockets/'
    )
    assert util.build_url('/', query={'test': 'test 1', 'test 2': 'test'}) == (
        'https://example.com/?test=test+1&test+2=test'
    )


def test_files(tmpdir):
    file_1 = tmpdir.join('file1.txt')
    file_1.write('content')
    file_2 = tmpdir.join('file2.txt')
    file_2.write('content')
    file_3 = tmpdir.join('file3.js')
    file_3.write('content')
    file_4 = tmpdir.join('file4.css')
    file_4.write('content')
    subdir = tmpdir.mkdir('subdir')
    ignored = subdir.join('ignored.txt')
    ignored.write('content')

    all_files = list(util.files(str(tmpdir)))
    assert len(all_files) == 4
    assert str(file_1) in all_files
    assert str(file_2) in all_files
    assert str(file_3) in all_files
    assert str(file_4) in all_files
    assert str(ignored) not in all_files

    txt_files = list(util.files(str(tmpdir), '*.txt'))
    assert len(txt_files) == 2
    assert str(file_1) in txt_files
    assert str(file_2) in txt_files
    assert str(file_3) not in txt_files
    assert str(file_4) not in txt_files
    assert str(ignored) not in txt_files


def test_single_cache():
    @util.single_cache
    def cached_time():
        return time()

    value = cached_time()
    assert cached_time() == value

    cached_time.cache_clear()
    new_value = cached_time()
    assert new_value > value
    assert cached_time() == new_value


def test_get_css_version(tmpdir, patch_config):
    # bypass cache
    get_css_version = util.get_css_version.__wrapped__

    with patch_config(static_dir=str(tmpdir)):
        assert get_css_version() == 0

        style = tmpdir.join('style.css')
        style.write('content')
        style.setmtime(500)
        assert get_css_version() == 500

        chat = tmpdir.join('chat.css')
        chat.write('content')
        chat.setmtime(250)
        assert get_css_version() == 500

        chat.setmtime(750)
        assert get_css_version() == 750

        unrelated = tmpdir.join('unrelated.txt')
        unrelated.write('content')
        unrelated.setmtime(1000)
        assert get_css_version() == 750

        style.setmtime(1250)
        assert get_css_version() == 1250


def test_get_js_version(tmpdir, patch_config):
    # bypass cache
    get_js_version = util.get_js_version.__wrapped__

    with patch_config(static_dir=str(tmpdir)):
        assert get_js_version() == 0

        scripts = tmpdir.join('scripts.js')
        scripts.write('content')
        scripts.setmtime(500)
        assert get_js_version() == 500

        chat = tmpdir.join('chat.js')
        chat.write('content')
        chat.setmtime(250)
        assert get_js_version() == 500

        chat.setmtime(750)
        assert get_js_version() == 750

        unrelated = tmpdir.join('unrelated.txt')
        unrelated.write('content')
        unrelated.setmtime(1000)
        assert get_js_version() == 750

        scripts.setmtime(1250)
        assert get_js_version() == 1250


def test_zhaddex(redisdb):
    ttl = 3600  # we don't test expiration in this test
    util.zhaddex(redisdb, 'messages', 'm-1', ttl, 'hello', time())
    assert util.zhgetall(redisdb, 'messages') == [b'hello']

    util.zhaddex(redisdb, 'messages', 'm-2', ttl, 'hi', time())
    assert util.zhgetall(redisdb, 'messages') == [b'hello', b'hi']

    util.zhaddex(redisdb, 'messages', 'm-3', ttl, 'prepend', 0.0)
    assert util.zhgetall(redisdb, 'messages') == [b'prepend', b'hello', b'hi']


def test_zhaddex_max_cardinality(redisdb):
    ttl = 3600  # we don't test expiration in this test
    util.zhaddex(redisdb, 'messages', 'm-1', ttl, 'hello', time(), 2)
    assert util.zhgetall(redisdb, 'messages') == [b'hello']

    util.zhaddex(redisdb, 'messages', 'm-2', ttl, 'hi', time(), 2)
    assert util.zhgetall(redisdb, 'messages') == [b'hello', b'hi']

    util.zhaddex(redisdb, 'messages', 'm-3', ttl, 'prepend', 0.0, 2)
    assert util.zhgetall(redisdb, 'messages') == [b'prepend', b'hi']

    util.zhaddex(redisdb, 'messages', 'm-4', ttl, 'normal', time(), 2)
    assert util.zhgetall(redisdb, 'messages') == [b'hi', b'normal']


# NOTE: TTL based tests can be considered potentially flaky, since redis
#       is responsible for evicting expired values. The granularity is
#       high enough that this should be extremely rare, but on a large
#       I/O stall it could potentially happen


@pytest.mark.flaky
def test_zhaddex_ttl(redisdb):
    util.zhaddex(redisdb, 'messages', 'm-1', 1, 'hello', time())
    util.zhaddex(redisdb, 'messages', 'm-2', 1, 'hi', time())
    assert util.zhgetall(redisdb, 'messages') == [b'hello', b'hi']

    sleep(1)
    assert util.zhgetall(redisdb, 'messages') == []


@pytest.mark.flaky
def test_zhttl(redisdb):
    util.zhaddex(redisdb, 'messages', 'm-1', 500, 'hello', time())
    util.zhaddex(redisdb, 'messages', 'm-2', 300, 'hi', time())
    assert util.zhttl(redisdb, 'messages', 'm-1') == 500
    assert util.zhttl(redisdb, 'messages', 'm-2') == 300


def test_zhmod(redisdb):
    ttl = 3600  # we don't test expiration in this test
    # this shouldn't raise an error but also not create a message
    util.zhmod(redisdb, 'messages', 'm-1', 'modified')
    assert util.zhgetall(redisdb, 'messages') == []

    util.zhaddex(redisdb, 'messages', 'm-1', ttl, 'hello', time())
    util.zhaddex(redisdb, 'messages', 'm-2', ttl, 'hi', time())
    assert util.zhgetall(redisdb, 'messages') == [b'hello', b'hi']

    util.zhmod(redisdb, 'messages', 'm-1', 'modified')
    assert util.zhgetall(redisdb, 'messages') == [b'modified', b'hi']

    util.zhmod(redisdb, 'messages', 'm-2', 'mod')
    assert util.zhgetall(redisdb, 'messages') == [b'modified', b'mod']


def test_zhdel(redisdb):
    ttl = 3600  # we don't test expiration in this test
    util.zhaddex(redisdb, 'messages', 'm-1', ttl, 'hello', time())
    util.zhaddex(redisdb, 'messages', 'm-2', ttl, 'hi', time())
    util.zhaddex(redisdb, 'messages', 'm-3', ttl, 'hola', time())
    assert util.zhgetall(redisdb, 'messages') == [b'hello', b'hi', b'hola']

    util.zhdel(redisdb, 'messages', 'nonexistant')
    assert util.zhgetall(redisdb, 'messages') == [b'hello', b'hi', b'hola']

    util.zhdel(redisdb, 'messages', 'm-1', 'm-3')
    assert util.zhgetall(redisdb, 'messages') == [b'hi']

    util.zhdel(redisdb, 'messages', 'm-2')
    assert util.zhgetall(redisdb, 'messages') == []


# NOTE: We convert results to sets to test the custom sh-Redis functions
#       this allows us to quickly test if all the expected elements are
#       there since the values will not be guaranteed to be sorted in a
#       predictable fashion. This is however not quite correct, since
#       multiple keys could share the same value, so we need to make sure
#       that we never use the same value for two keys in these tests.


def test_shaddex(redisdb):
    ttl = 3600  # we don't test expiration in this test
    util.shaddex(redisdb, 'messages', 'm-1', ttl, 'hello')
    assert set(util.shgetall(redisdb, 'messages')) == {b'hello'}

    util.shaddex(redisdb, 'messages', 'm-2', ttl, 'hi')
    assert set(util.shgetall(redisdb, 'messages')) == {b'hello', b'hi'}

    util.shaddex(redisdb, 'messages', 'm-3', ttl, 'hola')
    assert set(util.shgetall(redisdb, 'messages')) == {
        b'hello', b'hi', b'hola'
    }


# NOTE: TTL based tests can be considered potentially flaky, since redis
#       is responsible for evicting expired values. The granularity is
#       high enough that this should be extremely rare, but on a large
#       I/O stall it could potentially happen


@pytest.mark.flaky
def test_shaddex_ttl(redisdb):
    util.shaddex(redisdb, 'messages', 'm-1', 1, 'hello')
    util.shaddex(redisdb, 'messages', 'm-2', 1, 'hi')
    assert set(util.shgetall(redisdb, 'messages')) == {b'hello', b'hi'}

    sleep(1)
    assert util.shgetall(redisdb, 'messages') == []


@pytest.mark.flaky
def test_shttl(redisdb):
    util.shaddex(redisdb, 'messages', 'm-1', 500, 'hello')
    util.shaddex(redisdb, 'messages', 'm-2', 300, 'hi')
    assert util.shttl(redisdb, 'messages', 'm-1') == 500
    assert util.shttl(redisdb, 'messages', 'm-2') == 300


def test_shmod(redisdb):
    ttl = 3600  # we don't test expiration in this test
    # this shouldn't raise an error but also not create a message
    util.shmod(redisdb, 'messages', 'm-1', 'modified')
    assert util.zhgetall(redisdb, 'messages') == []

    util.shaddex(redisdb, 'messages', 'm-1', ttl, 'hello')
    util.shaddex(redisdb, 'messages', 'm-2', ttl, 'hi')
    assert set(util.shgetall(redisdb, 'messages')) == {b'hello', b'hi'}

    util.shmod(redisdb, 'messages', 'm-1', 'modified')
    assert set(util.shgetall(redisdb, 'messages')) == {b'modified', b'hi'}

    util.shmod(redisdb, 'messages', 'm-2', 'mod')
    assert set(util.shgetall(redisdb, 'messages')) == {b'modified', b'mod'}


def test_shdel(redisdb):
    ttl = 3600  # we don't test expiration in this test
    util.shaddex(redisdb, 'messages', 'm-1', ttl, 'hello')
    util.shaddex(redisdb, 'messages', 'm-2', ttl, 'hi')
    util.shaddex(redisdb, 'messages', 'm-3', ttl, 'hola')
    assert set(util.shgetall(redisdb, 'messages')) == {
        b'hello', b'hi', b'hola'
    }

    util.shdel(redisdb, 'messages', 'nonexistant')
    assert set(util.shgetall(redisdb, 'messages')) == {
        b'hello', b'hi', b'hola'
    }

    util.shdel(redisdb, 'messages', 'm-1', 'm-3')
    assert set(util.shgetall(redisdb, 'messages')) == {b'hi'}

    util.shdel(redisdb, 'messages', 'm-2')
    assert util.shgetall(redisdb, 'messages') == []


def test_shget(redisdb):
    ttl = 3600  # we don't test expiration in this test
    util.shaddex(redisdb, 'messages', 'm-1', ttl, 'hello')
    util.shaddex(redisdb, 'messages', 'm-2', ttl, 'hi')
    util.shaddex(redisdb, 'messages', 'm-3', ttl, 'hola')
    assert util.shget(redisdb, 'messages', 'm-1') == b'hello'
    assert util.shget(redisdb, 'messages', 'm-2') == b'hi'
    assert util.shget(redisdb, 'messages', 'm-3') == b'hola'
    assert util.shget(redisdb, 'messages', 'nonexistant') is None

from turbo_sticks.properties import get_property, set_property
from turbo_sticks.util import encrypt


def test_get_property(db):
    assert get_property('test') == ''
    assert get_property('test', 'default') == 'default'

    with db.connection() as conn:
        conn.execute(
            "INSERT INTO properties (value, key) "
            f"VALUES ('{encrypt('test')}', 'test')"
        )

    assert get_property('test') == 'test'
    assert get_property('test', 'default') == 'test'


def test_set_property(db):
    set_property('test', 'test')
    assert get_property('test') == 'test'

    # NOTE: We may wish to change this behaviour, it is a bit weird...
    set_property('test', None)
    assert get_property('test') == 'test'

    set_property('test', '')
    assert get_property('test') == 'test'

    set_property('test', 'test')
    assert get_property('test') == 'test'

    set_property('test', 'new')
    assert get_property('test') == 'new'

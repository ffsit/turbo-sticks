import pytest

from turbo_sticks.templates import render
from turbo_sticks.views import basic_page_data


def test_render():
    with pytest.raises(KeyError):
        render('main')

    page_data = basic_page_data('home')
    page_data['login_uri'] = ''
    rendered = render('main', page_data)
    assert len(rendered) > 0
    assert isinstance(rendered, bytes)

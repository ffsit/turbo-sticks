import pytest

from turbo_sticks.enums import ACL
from turbo_sticks.navigation import (
    render_navigation, set_nav_item, set_nav_external_item
)


@pytest.fixture
def navigation(monkeypatch):
    items = {}
    monkeypatch.setattr('turbo_sticks.navigation.items', items)
    yield items


def test_set_nav_item(navigation):
    assert len(navigation) == 0

    set_nav_item('theatre')
    assert len(navigation) == 1
    assert 'theatre' in navigation

    nav_item = navigation['theatre']
    assert nav_item.min_access_level == ACL.guest
    assert nav_item.max_access_level == ACL.admin

    set_nav_item('login', max_access_level=ACL.patron)
    assert len(navigation) == 2

    nav_item = navigation['login']
    assert nav_item.min_access_level == ACL.guest
    assert nav_item.max_access_level == ACL.patron

    set_nav_item('logout', min_access_level=ACL.turbo)
    assert len(navigation) == 3

    nav_item = navigation['logout']
    assert nav_item.min_access_level == ACL.turbo
    assert nav_item.max_access_level == ACL.admin


def test_set_nav_external_item(navigation):
    assert len(navigation) == 0

    set_nav_external_item('toot', 'TURBO Toot', 'https://turbo.chat')
    assert len(navigation) == 1
    assert 'toot' in navigation

    nav_item = navigation['toot']
    assert nav_item.min_access_level == ACL.guest
    assert nav_item.max_access_level == ACL.admin
    assert nav_item.view.display_name == 'TURBO Toot'
    assert nav_item.view.uri == 'https://turbo.chat'
    assert nav_item.view.path is None
    assert nav_item.view.view is None


def test_render_navigation(navigation):
    set_nav_item('theatre')
    set_nav_item('login', max_access_level=ACL.patron)
    set_nav_item('logout', min_access_level=ACL.turbo)
    set_nav_external_item('toot', 'TURBO Toot', 'https://turbo.chat')
    assert len(navigation) == 4

    rendered = render_navigation('toot')
    assert 'id="nav" class="no-js"' in rendered
    assert '<li><span>TURBO Toot</span></li>' in rendered
    assert '/theatre' in rendered
    assert '/login' in rendered
    assert '/login?redirect_to' not in rendered
    assert '/logout' not in rendered
    assert 'https://turbo.chat' not in rendered
    assert 'target="_blank"' not in rendered
    assert rendered.count('<li>') == 3

    rendered = render_navigation('theatre', expanded=True)
    assert 'id="nav" class="no-js hover"' in rendered
    assert '/theatre' not in rendered
    assert '/login' in rendered
    assert '/login?redirect_to=%2Ftheatre' in rendered
    assert '/logout' not in rendered
    assert '<a href="https://turbo.chat" target="_blank">' in rendered
    assert rendered.count('<li>') == 3

    rendered = render_navigation('theatre', access_level=ACL.turbo)
    assert '/theatre' not in rendered
    assert '/login' not in rendered
    assert '/logout' in rendered
    assert '<a href="https://turbo.chat" target="_blank">' in rendered
    assert rendered.count('<li>') == 3

from __future__ import annotations

from urllib.parse import quote_plus
from typing import NamedTuple, TYPE_CHECKING

from turbo_sticks.enums import ACL
from turbo_sticks.user import User

if TYPE_CHECKING:
    from .views import View


items = {}


class NavigationItem(NamedTuple):
    view:             View
    max_access_level: ACL = ACL.admin
    min_access_level: ACL = ACL.guest


# List of nav items
def set_nav_item(
    name:             str,
    max_access_level: ACL = ACL.admin,
    min_access_level: ACL = ACL.guest
) -> None:

    from turbo_sticks.views import views
    items[name] = NavigationItem(
        views[name], max_access_level, min_access_level
    )


def set_nav_external_item(
    name:             str,
    display_name:     str,
    uri:              str,
    max_access_level: ACL = ACL.admin,
    min_access_level: ACL = ACL.guest
) -> None:

    from turbo_sticks.views import View
    view = View(display_name, uri=uri)
    items[name] = NavigationItem(view, max_access_level, min_access_level)


def render_navigation(
    page_name:    str,
    user:         User | None = None,
    *,
    access_level: ACL | None = None,
    expanded:     bool = False
) -> str:

    if access_level is None:
        access_level = User.get_access_level(user)

    page_item = items.get(page_name)
    hover = ' hover' if expanded else ''
    html = f'\t<ul id="nav" class="no-js{hover}" aria-haspopup="true">\n'
    html += '\t\t<li class="arrow down"><span></span></li>\n'
    for name, item in items.items():
        view = item.view
        if item.max_access_level >= access_level >= item.min_access_level:
            if name == page_name:
                html += f'\t\t<li><span>{view.display_name}</span></li>\n'
            else:
                target = ''
                item_uri = view.path
                if not item_uri:
                    # External item
                    target = ' target="_blank"'
                    item_uri = view.uri

                # Add redirect_to for current page to the login nav-item
                if name == 'login' and page_item is not None:
                    if page_item.view.path is not None:
                        redirect_to = quote_plus(page_item.view.path)
                        item_uri = f'{view.path}?redirect_to={redirect_to}'

                html += '\t\t<li>'
                html += f'<a href="{item_uri}"{target}>{view.display_name}</a>'
                html += '</li>\n'
    html += '\t\t<li class="arrow up"><span></span></li>\n\t</ul>'
    return html

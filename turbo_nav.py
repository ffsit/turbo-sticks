import sys
from collections import OrderedDict
from urllib.parse import quote_plus
from turbo_user import ACL, User
this = sys.modules[__name__]

# Nav Items
this.items = OrderedDict()


class nav_item:
    def __init__(self, turbo_view, max_access_level=ACL.admin,
                 min_access_level=ACL.guest):
        self.turbo_view = turbo_view
        self.max_access_level = max_access_level
        self.min_access_level = min_access_level


def generate_html(page_name, user=None, **kwargs):
    access_level = kwargs.get('access_level', User.get_access_level(user))
    page_item = this.items.get(page_name)
    hover = ' hover' if kwargs.get('expanded', False) else ''
    html = f'\t<ul id="nav" class="no-js{hover}" aria-haspopup="true">\n'
    html += '\t\t<li class="arrow down"><span></span></li>\n'
    for name in this.items:
        item = this.items[name]
        view = item.turbo_view
        if item.max_access_level >= access_level >= item.min_access_level:
            if name == page_name:
                html += f'\t\t<li><span>{view.display_name}</span></li>\n'
            else:
                item_uri = view.path
                if not item_uri:
                    item_uri = view.uri
                # Add redirect_to for current page to the login nav-item
                if name == 'login' and page_item is not None:
                    redirect_to = quote_plus(page_item.turbo_view.path)
                    item_uri = f'{view.path}?redirect_to={redirect_to}'

                html += '\t\t<li>'
                html += f'<a href="{item_uri}">{view.display_name}</a>'
                html += '</li>\n'
    html += '\t\t<li class="arrow up"><span></span></li>\n\t</ul>'
    return html

import sys
from collections import OrderedDict
from urllib.parse import quote_plus

this = sys.modules[__name__]

# Nav Items
this.items = OrderedDict()


class nav_item:
    def __init__(self, turbo_view, hidden_when_logged_out=False,
                 hidden_when_logged_in=False):
        self.turbo_view = turbo_view
        self.hidden_when_logged_out = hidden_when_logged_out
        self.hidden_when_logged_in = hidden_when_logged_in


def generate_html(page_name, logged_in=False, expanded=False):
    page_item = this.items.get(page_name)
    hover = ' hover' if expanded else ''
    html = '\t<ul id="nav" class="no-js%s" aria-haspopup="true">\n' % (hover,)
    html += '\t\t<li class="arrow down"><span></span></li>\n'
    for name in this.items:
        item = this.items[name]
        view = item.turbo_view
        if((not logged_in and not item.hidden_when_logged_out) or
           (logged_in and not item.hidden_when_logged_in)):
            if name == page_name:
                html += '\t\t<li><span>%s</span></li>\n' % (view.display_name,)
            else:
                item_uri = view.uri
                # Add redirect_to for current page to the login nav-item
                if name == 'login' and page_item is not None:
                    redirect_to = quote_plus(page_item.turbo_view.uri)
                    item_uri = '%s?redirect_to=%s' % (view.uri, redirect_to)

                html += '\t\t<li>'
                html += '<a href="%s">%s</a>' % (item_uri, view.display_name)
                html += '</li>\n'
    html += '\t\t<li class="arrow up"><span></span></li>\n\t</ul>'
    return html

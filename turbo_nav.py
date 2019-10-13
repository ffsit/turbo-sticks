import sys
from collections import OrderedDict
from urllib import parse

this = sys.modules[__name__]

# Nav Items
this.items = OrderedDict();

class nav_item:
	def __init__(self, turbo_view, hidden_when_logged_out=False, hidden_when_logged_in=False):
		self.turbo_view = turbo_view
		self.hidden_when_logged_out = hidden_when_logged_out
		self.hidden_when_logged_in = hidden_when_logged_in

def generate_html(page_name, logged_in=False, expanded=False):
	page_item = this.items.get(page_name)
	result = '\t<ul id="nav" class="no-js' + (' hover' if expanded else '') + '" aria-haspopup="true">\n\t\t<li class="arrow down"><span></span></li>\n'
	for name in this.items:
		item = this.items[name]
		view = item.turbo_view
		if((not logged_in and not item.hidden_when_logged_out) or (logged_in and not item.hidden_when_logged_in)):
			if name == page_name:
				result += '\t\t<li><span>%s</span></li>\n' % (view.display_name)
			else:
				item_uri = view.uri
				# Add redirect_to for current page to the login nav-item
				if name == 'login' and page_item is not None:
					item_uri = view.uri + '?redirect_to=' + parse.quote_plus(page_item.turbo_view.uri)

				result += '\t\t<li><a href="%s">%s</a></li>\n' % (item_uri, view.display_name)
	result += '\t\t<li class="arrow up"><span></span></li>\n\t</ul>'
	return result

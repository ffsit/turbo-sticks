# HTML Template Handling - Read Files in folder templates and import them into the string maps 'pages' and 'blocks'
import os
from fnmatch import fnmatch

def files(path, pattern='*'):
	for entry in os.listdir(path):
		if fnmatch(entry, pattern):
			file_path = os.path.join(path, entry)
			if os.path.isfile(file_path):
				yield file_path

file_pattern = '*.html'

blocks = {}
blocks_path = './templates/blocks'
for file_path in files(blocks_path, file_pattern):
	block_name = os.path.splitext(os.path.basename(file_path))[0]
	with open(file_path) as f:
		blocks[block_name] = f.read().decode('utf-8')

pages = {}
pages_path = './templates/pages'
for file_path in files(pages_path, file_pattern):
	page_name = os.path.splitext(os.path.basename(file_path))[0]
	with open(file_path) as f:
		pages[page_name] = f.read().decode('utf-8')

def render(page_name, data={}):
	content = pages.get(page_name, 'Template not found.')
	result = content % blocks % data
	return result.encode('utf-8')
import logging

from turbo_sticks.config import debug_mode

__version__ = '3.0.2'

# Setup logging
logging.basicConfig(
    format='[%(asctime)s] %(levelname)-8s - %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    style='%',
    level=logging.DEBUG if debug_mode else logging.INFO,
)

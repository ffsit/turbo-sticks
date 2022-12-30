import pydantic
import pytest


def test_max_ge_min_db_pool(patch_config):
    with pytest.raises(pydantic.ValidationError):
        with patch_config(db_pool={'min_size': 4, 'max_size': 2}):
            pass

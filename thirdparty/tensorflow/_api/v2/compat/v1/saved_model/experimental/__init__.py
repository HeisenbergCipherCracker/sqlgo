# This file is MACHINE GENERATED! Do not edit.
# Generated by: tensorflow/python/tools/api/generator2/generator/generator.py script.
"""Public API for tf._api.v2.saved_model.experimental namespace
"""

import sys as _sys

from tensorflow.python.saved_model.save import save # line: 1145
from tensorflow.python.saved_model.save_options import VariablePolicy # line: 26
from tensorflow.python.trackable.resource import TrackableResource # line: 233

from tensorflow.python.util import module_wrapper as _module_wrapper

if not isinstance(_sys.modules[__name__], _module_wrapper.TFModuleWrapper):
  _sys.modules[__name__] = _module_wrapper.TFModuleWrapper(
      _sys.modules[__name__], "saved_model.experimental", public_apis=None, deprecation=False,
      has_lite=False)
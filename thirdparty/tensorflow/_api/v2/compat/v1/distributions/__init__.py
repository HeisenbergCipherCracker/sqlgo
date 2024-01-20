# This file is MACHINE GENERATED! Do not edit.
# Generated by: tensorflow/python/tools/api/generator2/generator/generator.py script.
"""Public API for tf._api.v2.distributions namespace
"""

import sys as _sys

from tensorflow.python.ops.distributions.bernoulli import Bernoulli # line: 31
from tensorflow.python.ops.distributions.beta import Beta # line: 46
from tensorflow.python.ops.distributions.categorical import Categorical # line: 58
from tensorflow.python.ops.distributions.dirichlet import Dirichlet # line: 44
from tensorflow.python.ops.distributions.dirichlet_multinomial import DirichletMultinomial # line: 50
from tensorflow.python.ops.distributions.distribution import Distribution # line: 272
from tensorflow.python.ops.distributions.distribution import FULLY_REPARAMETERIZED # line: 260
from tensorflow.python.ops.distributions.distribution import NOT_REPARAMETERIZED # line: 268
from tensorflow.python.ops.distributions.distribution import ReparameterizationType # line: 209
from tensorflow.python.ops.distributions.exponential import Exponential # line: 36
from tensorflow.python.ops.distributions.gamma import Gamma # line: 42
from tensorflow.python.ops.distributions.kullback_leibler import RegisterKL # line: 161
from tensorflow.python.ops.distributions.kullback_leibler import kl_divergence # line: 59
from tensorflow.python.ops.distributions.laplace import Laplace # line: 42
from tensorflow.python.ops.distributions.multinomial import Multinomial # line: 51
from tensorflow.python.ops.distributions.normal import Normal # line: 41
from tensorflow.python.ops.distributions.student_t import StudentT # line: 42
from tensorflow.python.ops.distributions.uniform import Uniform # line: 32

from tensorflow.python.util import module_wrapper as _module_wrapper

if not isinstance(_sys.modules[__name__], _module_wrapper.TFModuleWrapper):
  _sys.modules[__name__] = _module_wrapper.TFModuleWrapper(
      _sys.modules[__name__], "distributions", public_apis=None, deprecation=False,
      has_lite=False)
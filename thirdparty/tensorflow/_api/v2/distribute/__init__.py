# This file is MACHINE GENERATED! Do not edit.
# Generated by: tensorflow/python/tools/api/generator2/generator/generator.py script.
"""Public API for tf._api.v2.distribute namespace
"""

import sys as _sys

from tensorflow._api.v2.distribute import cluster_resolver
from tensorflow._api.v2.distribute import coordinator
from tensorflow._api.v2.distribute import experimental
from tensorflow.python.distribute.collective_all_reduce_strategy import CollectiveAllReduceStrategy as MultiWorkerMirroredStrategy # line: 56
from tensorflow.python.distribute.cross_device_ops import CrossDeviceOps # line: 251
from tensorflow.python.distribute.cross_device_ops import HierarchicalCopyAllReduce # line: 996
from tensorflow.python.distribute.cross_device_ops import NcclAllReduce # line: 959
from tensorflow.python.distribute.cross_device_ops import ReductionToOneDevice # line: 581
from tensorflow.python.distribute.distribute_lib import InputContext # line: 841
from tensorflow.python.distribute.distribute_lib import InputOptions # line: 1015
from tensorflow.python.distribute.distribute_lib import InputReplicationMode # line: 824
from tensorflow.python.distribute.distribute_lib import ReplicaContext # line: 3677
from tensorflow.python.distribute.distribute_lib import RunOptions # line: 980
from tensorflow.python.distribute.distribute_lib import Strategy # line: 2033
from tensorflow.python.distribute.distribute_lib import StrategyExtendedV2 as StrategyExtended # line: 2401
from tensorflow.python.distribute.distribute_lib import experimental_set_strategy # line: 584
from tensorflow.python.distribute.distribute_lib import get_replica_context # line: 454
from tensorflow.python.distribute.distribute_lib import get_strategy # line: 543
from tensorflow.python.distribute.distribute_lib import has_strategy # line: 563
from tensorflow.python.distribute.distribute_lib import in_cross_replica_context # line: 518
from tensorflow.python.distribute.mirrored_strategy import MirroredStrategy # line: 199
from tensorflow.python.distribute.one_device_strategy import OneDeviceStrategy # line: 38
from tensorflow.python.distribute.parameter_server_strategy_v2 import ParameterServerStrategyV2 as ParameterServerStrategy # line: 72
from tensorflow.python.distribute.reduce_util import ReduceOp # line: 23
from tensorflow.python.distribute.tpu_strategy import TPUStrategyV2 as TPUStrategy # line: 242
from tensorflow.python.training.server_lib import Server # line: 94
from tensorflow.python.types.distribute import DistributedDatasetInterface as DistributedDataset # line: 307
from tensorflow.python.types.distribute import DistributedIteratorInterface as DistributedIterator # line: 196
from tensorflow.python.types.distribute import DistributedValues # line: 62
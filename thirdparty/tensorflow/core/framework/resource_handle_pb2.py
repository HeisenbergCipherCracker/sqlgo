# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: tensorflow/core/framework/resource_handle.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from tensorflow.core.framework import tensor_shape_pb2 as tensorflow_dot_core_dot_framework_dot_tensor__shape__pb2
from tensorflow.core.framework import types_pb2 as tensorflow_dot_core_dot_framework_dot_types__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n/tensorflow/core/framework/resource_handle.proto\x12\ntensorflow\x1a,tensorflow/core/framework/tensor_shape.proto\x1a%tensorflow/core/framework/types.proto\"\xa5\x02\n\x13ResourceHandleProto\x12\x0e\n\x06\x64\x65vice\x18\x01 \x01(\t\x12\x11\n\tcontainer\x18\x02 \x01(\t\x12\x0c\n\x04name\x18\x03 \x01(\t\x12\x11\n\thash_code\x18\x04 \x01(\x04\x12\x17\n\x0fmaybe_type_name\x18\x05 \x01(\t\x12H\n\x11\x64types_and_shapes\x18\x06 \x03(\x0b\x32-.tensorflow.ResourceHandleProto.DtypeAndShape\x1a\x61\n\rDtypeAndShape\x12#\n\x05\x64type\x18\x01 \x01(\x0e\x32\x14.tensorflow.DataType\x12+\n\x05shape\x18\x02 \x01(\x0b\x32\x1c.tensorflow.TensorShapeProtoJ\x04\x08\x07\x10\x08\x42\x87\x01\n\x18org.tensorflow.frameworkB\x0eResourceHandleP\x01ZVgithub.com/tensorflow/tensorflow/tensorflow/go/core/framework/resource_handle_go_proto\xf8\x01\x01\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'tensorflow.core.framework.resource_handle_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\030org.tensorflow.frameworkB\016ResourceHandleP\001ZVgithub.com/tensorflow/tensorflow/tensorflow/go/core/framework/resource_handle_go_proto\370\001\001'
  _RESOURCEHANDLEPROTO._serialized_start=149
  _RESOURCEHANDLEPROTO._serialized_end=442
  _RESOURCEHANDLEPROTO_DTYPEANDSHAPE._serialized_start=339
  _RESOURCEHANDLEPROTO_DTYPEANDSHAPE._serialized_end=436
# @@protoc_insertion_point(module_scope)
# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: tensorboard/compat/proto/tensor_shape.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n+tensorboard/compat/proto/tensor_shape.proto\x12\x0btensorboard\"{\n\x10TensorShapeProto\x12.\n\x03\x64im\x18\x02 \x03(\x0b\x32!.tensorboard.TensorShapeProto.Dim\x12\x14\n\x0cunknown_rank\x18\x03 \x01(\x08\x1a!\n\x03\x44im\x12\x0c\n\x04size\x18\x01 \x01(\x03\x12\x0c\n\x04name\x18\x02 \x01(\tB\x87\x01\n\x18org.tensorflow.frameworkB\x11TensorShapeProtosP\x01ZSgithub.com/tensorflow/tensorflow/tensorflow/go/core/framework/tensor_shape_go_proto\xf8\x01\x01\x62\x06proto3')



_TENSORSHAPEPROTO = DESCRIPTOR.message_types_by_name['TensorShapeProto']
_TENSORSHAPEPROTO_DIM = _TENSORSHAPEPROTO.nested_types_by_name['Dim']
TensorShapeProto = _reflection.GeneratedProtocolMessageType('TensorShapeProto', (_message.Message,), {

  'Dim' : _reflection.GeneratedProtocolMessageType('Dim', (_message.Message,), {
    'DESCRIPTOR' : _TENSORSHAPEPROTO_DIM,
    '__module__' : 'tensorboard.compat.proto.tensor_shape_pb2'
    # @@protoc_insertion_point(class_scope:tensorboard.TensorShapeProto.Dim)
    })
  ,
  'DESCRIPTOR' : _TENSORSHAPEPROTO,
  '__module__' : 'tensorboard.compat.proto.tensor_shape_pb2'
  # @@protoc_insertion_point(class_scope:tensorboard.TensorShapeProto)
  })
_sym_db.RegisterMessage(TensorShapeProto)
_sym_db.RegisterMessage(TensorShapeProto.Dim)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\030org.tensorflow.frameworkB\021TensorShapeProtosP\001ZSgithub.com/tensorflow/tensorflow/tensorflow/go/core/framework/tensor_shape_go_proto\370\001\001'
  _TENSORSHAPEPROTO._serialized_start=60
  _TENSORSHAPEPROTO._serialized_end=183
  _TENSORSHAPEPROTO_DIM._serialized_start=150
  _TENSORSHAPEPROTO_DIM._serialized_end=183
# @@protoc_insertion_point(module_scope)
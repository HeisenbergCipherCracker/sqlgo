# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: tensorboard/compat/proto/graph_debug_info.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n/tensorboard/compat/proto/graph_debug_info.proto\x12\x0btensorboard\"\xab\x06\n\x0eGraphDebugInfo\x12\r\n\x05\x66iles\x18\x01 \x03(\t\x12\x41\n\x0c\x66rames_by_id\x18\x04 \x03(\x0b\x32+.tensorboard.GraphDebugInfo.FramesByIdEntry\x12\x41\n\x0ctraces_by_id\x18\x06 \x03(\x0b\x32+.tensorboard.GraphDebugInfo.TracesByIdEntry\x12\x37\n\x06traces\x18\x02 \x03(\x0b\x32\'.tensorboard.GraphDebugInfo.TracesEntry\x12H\n\x10name_to_trace_id\x18\x05 \x03(\x0b\x32..tensorboard.GraphDebugInfo.NameToTraceIdEntry\x1aX\n\x0b\x46ileLineCol\x12\x12\n\nfile_index\x18\x01 \x01(\x05\x12\x0c\n\x04line\x18\x02 \x01(\x05\x12\x0b\n\x03\x63ol\x18\x03 \x01(\x05\x12\x0c\n\x04\x66unc\x18\x04 \x01(\t\x12\x0c\n\x04\x63ode\x18\x05 \x01(\t\x1a\x63\n\nStackTrace\x12?\n\x0e\x66ile_line_cols\x18\x01 \x03(\x0b\x32\'.tensorboard.GraphDebugInfo.FileLineCol\x12\x14\n\x08\x66rame_id\x18\x02 \x03(\x06\x42\x02\x10\x01\x1aZ\n\x0f\x46ramesByIdEntry\x12\x0b\n\x03key\x18\x01 \x01(\x06\x12\x36\n\x05value\x18\x02 \x01(\x0b\x32\'.tensorboard.GraphDebugInfo.FileLineCol:\x02\x38\x01\x1aY\n\x0fTracesByIdEntry\x12\x0b\n\x03key\x18\x01 \x01(\x06\x12\x35\n\x05value\x18\x02 \x01(\x0b\x32&.tensorboard.GraphDebugInfo.StackTrace:\x02\x38\x01\x1aU\n\x0bTracesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x35\n\x05value\x18\x02 \x01(\x0b\x32&.tensorboard.GraphDebugInfo.StackTrace:\x02\x38\x01\x1a\x34\n\x12NameToTraceIdEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x06:\x02\x38\x01\x42\x8c\x01\n\x18org.tensorflow.frameworkB\x14GraphDebugInfoProtosP\x01ZUgithub.com/tensorflow/tensorflow/tensorflow/go/core/protobuf/for_core_protos_go_proto\xf8\x01\x01')



_GRAPHDEBUGINFO = DESCRIPTOR.message_types_by_name['GraphDebugInfo']
_GRAPHDEBUGINFO_FILELINECOL = _GRAPHDEBUGINFO.nested_types_by_name['FileLineCol']
_GRAPHDEBUGINFO_STACKTRACE = _GRAPHDEBUGINFO.nested_types_by_name['StackTrace']
_GRAPHDEBUGINFO_FRAMESBYIDENTRY = _GRAPHDEBUGINFO.nested_types_by_name['FramesByIdEntry']
_GRAPHDEBUGINFO_TRACESBYIDENTRY = _GRAPHDEBUGINFO.nested_types_by_name['TracesByIdEntry']
_GRAPHDEBUGINFO_TRACESENTRY = _GRAPHDEBUGINFO.nested_types_by_name['TracesEntry']
_GRAPHDEBUGINFO_NAMETOTRACEIDENTRY = _GRAPHDEBUGINFO.nested_types_by_name['NameToTraceIdEntry']
GraphDebugInfo = _reflection.GeneratedProtocolMessageType('GraphDebugInfo', (_message.Message,), {

  'FileLineCol' : _reflection.GeneratedProtocolMessageType('FileLineCol', (_message.Message,), {
    'DESCRIPTOR' : _GRAPHDEBUGINFO_FILELINECOL,
    '__module__' : 'tensorboard.compat.proto.graph_debug_info_pb2'
    # @@protoc_insertion_point(class_scope:tensorboard.GraphDebugInfo.FileLineCol)
    })
  ,

  'StackTrace' : _reflection.GeneratedProtocolMessageType('StackTrace', (_message.Message,), {
    'DESCRIPTOR' : _GRAPHDEBUGINFO_STACKTRACE,
    '__module__' : 'tensorboard.compat.proto.graph_debug_info_pb2'
    # @@protoc_insertion_point(class_scope:tensorboard.GraphDebugInfo.StackTrace)
    })
  ,

  'FramesByIdEntry' : _reflection.GeneratedProtocolMessageType('FramesByIdEntry', (_message.Message,), {
    'DESCRIPTOR' : _GRAPHDEBUGINFO_FRAMESBYIDENTRY,
    '__module__' : 'tensorboard.compat.proto.graph_debug_info_pb2'
    # @@protoc_insertion_point(class_scope:tensorboard.GraphDebugInfo.FramesByIdEntry)
    })
  ,

  'TracesByIdEntry' : _reflection.GeneratedProtocolMessageType('TracesByIdEntry', (_message.Message,), {
    'DESCRIPTOR' : _GRAPHDEBUGINFO_TRACESBYIDENTRY,
    '__module__' : 'tensorboard.compat.proto.graph_debug_info_pb2'
    # @@protoc_insertion_point(class_scope:tensorboard.GraphDebugInfo.TracesByIdEntry)
    })
  ,

  'TracesEntry' : _reflection.GeneratedProtocolMessageType('TracesEntry', (_message.Message,), {
    'DESCRIPTOR' : _GRAPHDEBUGINFO_TRACESENTRY,
    '__module__' : 'tensorboard.compat.proto.graph_debug_info_pb2'
    # @@protoc_insertion_point(class_scope:tensorboard.GraphDebugInfo.TracesEntry)
    })
  ,

  'NameToTraceIdEntry' : _reflection.GeneratedProtocolMessageType('NameToTraceIdEntry', (_message.Message,), {
    'DESCRIPTOR' : _GRAPHDEBUGINFO_NAMETOTRACEIDENTRY,
    '__module__' : 'tensorboard.compat.proto.graph_debug_info_pb2'
    # @@protoc_insertion_point(class_scope:tensorboard.GraphDebugInfo.NameToTraceIdEntry)
    })
  ,
  'DESCRIPTOR' : _GRAPHDEBUGINFO,
  '__module__' : 'tensorboard.compat.proto.graph_debug_info_pb2'
  # @@protoc_insertion_point(class_scope:tensorboard.GraphDebugInfo)
  })
_sym_db.RegisterMessage(GraphDebugInfo)
_sym_db.RegisterMessage(GraphDebugInfo.FileLineCol)
_sym_db.RegisterMessage(GraphDebugInfo.StackTrace)
_sym_db.RegisterMessage(GraphDebugInfo.FramesByIdEntry)
_sym_db.RegisterMessage(GraphDebugInfo.TracesByIdEntry)
_sym_db.RegisterMessage(GraphDebugInfo.TracesEntry)
_sym_db.RegisterMessage(GraphDebugInfo.NameToTraceIdEntry)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\030org.tensorflow.frameworkB\024GraphDebugInfoProtosP\001ZUgithub.com/tensorflow/tensorflow/tensorflow/go/core/protobuf/for_core_protos_go_proto\370\001\001'
  _GRAPHDEBUGINFO_STACKTRACE.fields_by_name['frame_id']._options = None
  _GRAPHDEBUGINFO_STACKTRACE.fields_by_name['frame_id']._serialized_options = b'\020\001'
  _GRAPHDEBUGINFO_FRAMESBYIDENTRY._options = None
  _GRAPHDEBUGINFO_FRAMESBYIDENTRY._serialized_options = b'8\001'
  _GRAPHDEBUGINFO_TRACESBYIDENTRY._options = None
  _GRAPHDEBUGINFO_TRACESBYIDENTRY._serialized_options = b'8\001'
  _GRAPHDEBUGINFO_TRACESENTRY._options = None
  _GRAPHDEBUGINFO_TRACESENTRY._serialized_options = b'8\001'
  _GRAPHDEBUGINFO_NAMETOTRACEIDENTRY._options = None
  _GRAPHDEBUGINFO_NAMETOTRACEIDENTRY._serialized_options = b'8\001'
  _GRAPHDEBUGINFO._serialized_start=65
  _GRAPHDEBUGINFO._serialized_end=876
  _GRAPHDEBUGINFO_FILELINECOL._serialized_start=363
  _GRAPHDEBUGINFO_FILELINECOL._serialized_end=451
  _GRAPHDEBUGINFO_STACKTRACE._serialized_start=453
  _GRAPHDEBUGINFO_STACKTRACE._serialized_end=552
  _GRAPHDEBUGINFO_FRAMESBYIDENTRY._serialized_start=554
  _GRAPHDEBUGINFO_FRAMESBYIDENTRY._serialized_end=644
  _GRAPHDEBUGINFO_TRACESBYIDENTRY._serialized_start=646
  _GRAPHDEBUGINFO_TRACESBYIDENTRY._serialized_end=735
  _GRAPHDEBUGINFO_TRACESENTRY._serialized_start=737
  _GRAPHDEBUGINFO_TRACESENTRY._serialized_end=822
  _GRAPHDEBUGINFO_NAMETOTRACEIDENTRY._serialized_start=824
  _GRAPHDEBUGINFO_NAMETOTRACEIDENTRY._serialized_end=876
# @@protoc_insertion_point(module_scope)
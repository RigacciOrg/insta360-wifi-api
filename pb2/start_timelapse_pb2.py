# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: start_timelapse.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import timelapse_pb2 as timelapse__pb2
import extra_info_pb2 as extra__info__pb2
try:
  offset__state__pb2 = extra__info__pb2.offset__state__pb2
except AttributeError:
  offset__state__pb2 = extra__info__pb2.offset_state_pb2
try:
  window__crop__info__pb2 = extra__info__pb2.window__crop__info__pb2
except AttributeError:
  window__crop__info__pb2 = extra__info__pb2.window_crop_info_pb2

from timelapse_pb2 import *
from extra_info_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='start_timelapse.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x15start_timelapse.proto\x12\x11insta360.messages\x1a\x0ftimelapse.proto\x1a\x10\x65xtra_info.proto\"z\n\x0eStartTimelapse\x12.\n\x04mode\x18\x01 \x01(\x0e\x32 .insta360.messages.TimelapseMode\x12\x38\n\x0e\x65xtra_metadata\x18\x02 \x01(\x0b\x32 .insta360.messages.ExtraMetadata\"\x14\n\x12StartTimelapseRespB\x08\xa2\x02\x05INSPBP\x00P\x01\x62\x06proto3'
  ,
  dependencies=[timelapse__pb2.DESCRIPTOR,extra__info__pb2.DESCRIPTOR,],
  public_dependencies=[timelapse__pb2.DESCRIPTOR,extra__info__pb2.DESCRIPTOR,])




_STARTTIMELAPSE = _descriptor.Descriptor(
  name='StartTimelapse',
  full_name='insta360.messages.StartTimelapse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='mode', full_name='insta360.messages.StartTimelapse.mode', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='extra_metadata', full_name='insta360.messages.StartTimelapse.extra_metadata', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=79,
  serialized_end=201,
)


_STARTTIMELAPSERESP = _descriptor.Descriptor(
  name='StartTimelapseResp',
  full_name='insta360.messages.StartTimelapseResp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=203,
  serialized_end=223,
)

_STARTTIMELAPSE.fields_by_name['mode'].enum_type = timelapse__pb2._TIMELAPSEMODE
_STARTTIMELAPSE.fields_by_name['extra_metadata'].message_type = extra__info__pb2._EXTRAMETADATA
DESCRIPTOR.message_types_by_name['StartTimelapse'] = _STARTTIMELAPSE
DESCRIPTOR.message_types_by_name['StartTimelapseResp'] = _STARTTIMELAPSERESP
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

StartTimelapse = _reflection.GeneratedProtocolMessageType('StartTimelapse', (_message.Message,), {
  'DESCRIPTOR' : _STARTTIMELAPSE,
  '__module__' : 'start_timelapse_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.StartTimelapse)
  })
_sym_db.RegisterMessage(StartTimelapse)

StartTimelapseResp = _reflection.GeneratedProtocolMessageType('StartTimelapseResp', (_message.Message,), {
  'DESCRIPTOR' : _STARTTIMELAPSERESP,
  '__module__' : 'start_timelapse_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.StartTimelapseResp)
  })
_sym_db.RegisterMessage(StartTimelapseResp)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
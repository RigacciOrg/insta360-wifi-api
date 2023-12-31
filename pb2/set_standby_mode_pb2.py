# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: set_standby_mode.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='set_standby_mode.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x16set_standby_mode.proto\x12\x11insta360.messages\"\xb5\x01\n\x0eSetStandbyMode\x12\x43\n\x0cstandby_mode\x18\x01 \x01(\x0e\x32-.insta360.messages.SetStandbyMode.StandbyMode\"^\n\x0bStandbyMode\x12\x18\n\x14STANDBY_MODE_UNKNOWN\x10\x00\x12\x1b\n\x17STANDBY_MODE_LOW_ENERGY\x10\x01\x12\x18\n\x14STANDBY_MODE_WAKE_UP\x10\x02\"\x14\n\x12SetStandbyModeRespB\x08\xa2\x02\x05INSPBb\x06proto3'
)



_SETSTANDBYMODE_STANDBYMODE = _descriptor.EnumDescriptor(
  name='StandbyMode',
  full_name='insta360.messages.SetStandbyMode.StandbyMode',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='STANDBY_MODE_UNKNOWN', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='STANDBY_MODE_LOW_ENERGY', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='STANDBY_MODE_WAKE_UP', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=133,
  serialized_end=227,
)
_sym_db.RegisterEnumDescriptor(_SETSTANDBYMODE_STANDBYMODE)


_SETSTANDBYMODE = _descriptor.Descriptor(
  name='SetStandbyMode',
  full_name='insta360.messages.SetStandbyMode',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='standby_mode', full_name='insta360.messages.SetStandbyMode.standby_mode', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _SETSTANDBYMODE_STANDBYMODE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=46,
  serialized_end=227,
)


_SETSTANDBYMODERESP = _descriptor.Descriptor(
  name='SetStandbyModeResp',
  full_name='insta360.messages.SetStandbyModeResp',
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
  serialized_start=229,
  serialized_end=249,
)

_SETSTANDBYMODE.fields_by_name['standby_mode'].enum_type = _SETSTANDBYMODE_STANDBYMODE
_SETSTANDBYMODE_STANDBYMODE.containing_type = _SETSTANDBYMODE
DESCRIPTOR.message_types_by_name['SetStandbyMode'] = _SETSTANDBYMODE
DESCRIPTOR.message_types_by_name['SetStandbyModeResp'] = _SETSTANDBYMODERESP
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SetStandbyMode = _reflection.GeneratedProtocolMessageType('SetStandbyMode', (_message.Message,), {
  'DESCRIPTOR' : _SETSTANDBYMODE,
  '__module__' : 'set_standby_mode_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.SetStandbyMode)
  })
_sym_db.RegisterMessage(SetStandbyMode)

SetStandbyModeResp = _reflection.GeneratedProtocolMessageType('SetStandbyModeResp', (_message.Message,), {
  'DESCRIPTOR' : _SETSTANDBYMODERESP,
  '__module__' : 'set_standby_mode_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.SetStandbyModeResp)
  })
_sym_db.RegisterMessage(SetStandbyModeResp)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)

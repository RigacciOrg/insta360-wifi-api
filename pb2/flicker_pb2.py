# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: flicker.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='flicker.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\rflicker.proto\x12\x11insta360.messages*?\n\x07\x46licker\x12\x10\n\x0c\x46LICKER_AUTO\x10\x00\x12\x10\n\x0c\x46LICKER_60HZ\x10\x01\x12\x10\n\x0c\x46LICKER_50HZ\x10\x02\x42\x08\xa2\x02\x05INSPBb\x06proto3'
)

_FLICKER = _descriptor.EnumDescriptor(
  name='Flicker',
  full_name='insta360.messages.Flicker',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='FLICKER_AUTO', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='FLICKER_60HZ', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='FLICKER_50HZ', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=36,
  serialized_end=99,
)
_sym_db.RegisterEnumDescriptor(_FLICKER)

Flicker = enum_type_wrapper.EnumTypeWrapper(_FLICKER)
FLICKER_AUTO = 0
FLICKER_60HZ = 1
FLICKER_50HZ = 2


DESCRIPTOR.enum_types_by_name['Flicker'] = _FLICKER
_sym_db.RegisterFileDescriptor(DESCRIPTOR)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)

# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: start_bullettime.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='start_bullettime.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x16start_bullettime.proto\x12\x11insta360.messages\"\x11\n\x0fStartBulletTime\"\x15\n\x13StartBulletTimeRespB\x08\xa2\x02\x05INSPBb\x06proto3'
)




_STARTBULLETTIME = _descriptor.Descriptor(
  name='StartBulletTime',
  full_name='insta360.messages.StartBulletTime',
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
  serialized_start=45,
  serialized_end=62,
)


_STARTBULLETTIMERESP = _descriptor.Descriptor(
  name='StartBulletTimeResp',
  full_name='insta360.messages.StartBulletTimeResp',
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
  serialized_start=64,
  serialized_end=85,
)

DESCRIPTOR.message_types_by_name['StartBulletTime'] = _STARTBULLETTIME
DESCRIPTOR.message_types_by_name['StartBulletTimeResp'] = _STARTBULLETTIMERESP
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

StartBulletTime = _reflection.GeneratedProtocolMessageType('StartBulletTime', (_message.Message,), {
  'DESCRIPTOR' : _STARTBULLETTIME,
  '__module__' : 'start_bullettime_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.StartBulletTime)
  })
_sym_db.RegisterMessage(StartBulletTime)

StartBulletTimeResp = _reflection.GeneratedProtocolMessageType('StartBulletTimeResp', (_message.Message,), {
  'DESCRIPTOR' : _STARTBULLETTIMERESP,
  '__module__' : 'start_bullettime_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.StartBulletTimeResp)
  })
_sym_db.RegisterMessage(StartBulletTimeResp)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)

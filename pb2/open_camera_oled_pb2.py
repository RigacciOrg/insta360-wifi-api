# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: open_camera_oled.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='open_camera_oled.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x16open_camera_oled.proto\x12\x11insta360.messages\"\x10\n\x0eOpenCameraOled\"\x14\n\x12OpenCameraOledRespB\x08\xa2\x02\x05INSPBb\x06proto3'
)




_OPENCAMERAOLED = _descriptor.Descriptor(
  name='OpenCameraOled',
  full_name='insta360.messages.OpenCameraOled',
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
  serialized_end=61,
)


_OPENCAMERAOLEDRESP = _descriptor.Descriptor(
  name='OpenCameraOledResp',
  full_name='insta360.messages.OpenCameraOledResp',
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
  serialized_start=63,
  serialized_end=83,
)

DESCRIPTOR.message_types_by_name['OpenCameraOled'] = _OPENCAMERAOLED
DESCRIPTOR.message_types_by_name['OpenCameraOledResp'] = _OPENCAMERAOLEDRESP
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

OpenCameraOled = _reflection.GeneratedProtocolMessageType('OpenCameraOled', (_message.Message,), {
  'DESCRIPTOR' : _OPENCAMERAOLED,
  '__module__' : 'open_camera_oled_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.OpenCameraOled)
  })
_sym_db.RegisterMessage(OpenCameraOled)

OpenCameraOledResp = _reflection.GeneratedProtocolMessageType('OpenCameraOledResp', (_message.Message,), {
  'DESCRIPTOR' : _OPENCAMERAOLEDRESP,
  '__module__' : 'open_camera_oled_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.OpenCameraOledResp)
  })
_sym_db.RegisterMessage(OpenCameraOledResp)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)

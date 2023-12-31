# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: get_photography_options.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import photography_options_pb2 as photography__options__pb2
try:
  video__pb2 = photography__options__pb2.video__pb2
except AttributeError:
  video__pb2 = photography__options__pb2.video_pb2
try:
  photo__pb2 = photography__options__pb2.photo__pb2
except AttributeError:
  photo__pb2 = photography__options__pb2.photo_pb2
try:
  flicker__pb2 = photography__options__pb2.flicker__pb2
except AttributeError:
  flicker__pb2 = photography__options__pb2.flicker_pb2
try:
  exposure__pb2 = photography__options__pb2.exposure__pb2
except AttributeError:
  exposure__pb2 = photography__options__pb2.exposure_pb2
import options_pb2 as options__pb2
try:
  photo__pb2 = options__pb2.photo__pb2
except AttributeError:
  photo__pb2 = options__pb2.photo_pb2
try:
  video__pb2 = options__pb2.video__pb2
except AttributeError:
  video__pb2 = options__pb2.video_pb2
try:
  battery__pb2 = options__pb2.battery__pb2
except AttributeError:
  battery__pb2 = options__pb2.battery_pb2
try:
  storage__pb2 = options__pb2.storage__pb2
except AttributeError:
  storage__pb2 = options__pb2.storage_pb2
try:
  button__press__pb2 = options__pb2.button__press__pb2
except AttributeError:
  button__press__pb2 = options__pb2.button_press_pb2
try:
  flicker__pb2 = options__pb2.flicker__pb2
except AttributeError:
  flicker__pb2 = options__pb2.flicker_pb2
try:
  sensor__pb2 = options__pb2.sensor__pb2
except AttributeError:
  sensor__pb2 = options__pb2.sensor_pb2
try:
  chargebox__pb2 = options__pb2.chargebox__pb2
except AttributeError:
  chargebox__pb2 = options__pb2.chargebox_pb2
try:
  battery__pb2 = options__pb2.battery__pb2
except AttributeError:
  battery__pb2 = options__pb2.battery_pb2
try:
  offset__state__pb2 = options__pb2.offset__state__pb2
except AttributeError:
  offset__state__pb2 = options__pb2.offset_state_pb2
try:
  window__crop__info__pb2 = options__pb2.window__crop__info__pb2
except AttributeError:
  window__crop__info__pb2 = options__pb2.window_crop_info_pb2

from photography_options_pb2 import *
from options_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='get_photography_options.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1dget_photography_options.proto\x12\x11insta360.messages\x1a\x19photography_options.proto\x1a\roptions.proto\"\x8f\x01\n\x15GetPhotographyOptions\x12>\n\x0coption_types\x18\x01 \x03(\x0e\x32(.insta360.messages.PhotographyOptionType\x12\x36\n\rfunction_mode\x18\x02 \x01(\x0e\x32\x1f.insta360.messages.FunctionMode\"\x91\x01\n\x19GetPhotographyOptionsResp\x12>\n\x0coption_types\x18\x01 \x03(\x0e\x32(.insta360.messages.PhotographyOptionType\x12\x34\n\x05value\x18\x02 \x01(\x0b\x32%.insta360.messages.PhotographyOptionsB\x08\xa2\x02\x05INSPBP\x00P\x01\x62\x06proto3'
  ,
  dependencies=[photography__options__pb2.DESCRIPTOR,options__pb2.DESCRIPTOR,],
  public_dependencies=[photography__options__pb2.DESCRIPTOR,options__pb2.DESCRIPTOR,])




_GETPHOTOGRAPHYOPTIONS = _descriptor.Descriptor(
  name='GetPhotographyOptions',
  full_name='insta360.messages.GetPhotographyOptions',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='option_types', full_name='insta360.messages.GetPhotographyOptions.option_types', index=0,
      number=1, type=14, cpp_type=8, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='function_mode', full_name='insta360.messages.GetPhotographyOptions.function_mode', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
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
  serialized_start=95,
  serialized_end=238,
)


_GETPHOTOGRAPHYOPTIONSRESP = _descriptor.Descriptor(
  name='GetPhotographyOptionsResp',
  full_name='insta360.messages.GetPhotographyOptionsResp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='option_types', full_name='insta360.messages.GetPhotographyOptionsResp.option_types', index=0,
      number=1, type=14, cpp_type=8, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='insta360.messages.GetPhotographyOptionsResp.value', index=1,
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
  serialized_start=241,
  serialized_end=386,
)

_GETPHOTOGRAPHYOPTIONS.fields_by_name['option_types'].enum_type = photography__options__pb2._PHOTOGRAPHYOPTIONTYPE
_GETPHOTOGRAPHYOPTIONS.fields_by_name['function_mode'].enum_type = options__pb2._FUNCTIONMODE
_GETPHOTOGRAPHYOPTIONSRESP.fields_by_name['option_types'].enum_type = photography__options__pb2._PHOTOGRAPHYOPTIONTYPE
_GETPHOTOGRAPHYOPTIONSRESP.fields_by_name['value'].message_type = photography__options__pb2._PHOTOGRAPHYOPTIONS
DESCRIPTOR.message_types_by_name['GetPhotographyOptions'] = _GETPHOTOGRAPHYOPTIONS
DESCRIPTOR.message_types_by_name['GetPhotographyOptionsResp'] = _GETPHOTOGRAPHYOPTIONSRESP
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

GetPhotographyOptions = _reflection.GeneratedProtocolMessageType('GetPhotographyOptions', (_message.Message,), {
  'DESCRIPTOR' : _GETPHOTOGRAPHYOPTIONS,
  '__module__' : 'get_photography_options_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.GetPhotographyOptions)
  })
_sym_db.RegisterMessage(GetPhotographyOptions)

GetPhotographyOptionsResp = _reflection.GeneratedProtocolMessageType('GetPhotographyOptionsResp', (_message.Message,), {
  'DESCRIPTOR' : _GETPHOTOGRAPHYOPTIONSRESP,
  '__module__' : 'get_photography_options_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.GetPhotographyOptionsResp)
  })
_sym_db.RegisterMessage(GetPhotographyOptionsResp)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)

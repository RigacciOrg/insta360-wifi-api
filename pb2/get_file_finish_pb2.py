# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: get_file_finish.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import file_type_pb2 as file__type__pb2
import track_pb2 as track__pb2
try:
  file__type__pb2 = track__pb2.file__type__pb2
except AttributeError:
  file__type__pb2 = track__pb2.file_type_pb2

from file_type_pb2 import *
from track_pb2 import *

DESCRIPTOR = _descriptor.FileDescriptor(
  name='get_file_finish.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x15get_file_finish.proto\x12\x11insta360.messages\x1a\x0f\x66ile_type.proto\x1a\x0btrack.proto\"t\n\rGetFileFinish\x12.\n\tfile_type\x18\x01 \x01(\x0e\x32\x1b.insta360.messages.FileType\x12\x33\n\x08\x64ownload\x18\x02 \x01(\x0e\x32!.insta360.messages.TransferStatusB\x08\xa2\x02\x05INSPBP\x00P\x01\x62\x06proto3'
  ,
  dependencies=[file__type__pb2.DESCRIPTOR,track__pb2.DESCRIPTOR,],
  public_dependencies=[file__type__pb2.DESCRIPTOR,track__pb2.DESCRIPTOR,])




_GETFILEFINISH = _descriptor.Descriptor(
  name='GetFileFinish',
  full_name='insta360.messages.GetFileFinish',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='file_type', full_name='insta360.messages.GetFileFinish.file_type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='download', full_name='insta360.messages.GetFileFinish.download', index=1,
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
  serialized_start=74,
  serialized_end=190,
)

_GETFILEFINISH.fields_by_name['file_type'].enum_type = file__type__pb2._FILETYPE
_GETFILEFINISH.fields_by_name['download'].enum_type = track__pb2._TRANSFERSTATUS
DESCRIPTOR.message_types_by_name['GetFileFinish'] = _GETFILEFINISH
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

GetFileFinish = _reflection.GeneratedProtocolMessageType('GetFileFinish', (_message.Message,), {
  'DESCRIPTOR' : _GETFILEFINISH,
  '__module__' : 'get_file_finish_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.GetFileFinish)
  })
_sym_db.RegisterMessage(GetFileFinish)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)

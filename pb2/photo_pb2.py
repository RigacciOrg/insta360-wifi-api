# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: photo.proto

from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='photo.proto',
  package='insta360.messages',
  syntax='proto3',
  serialized_options=b'\242\002\005INSPB',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0bphoto.proto\x12\x11insta360.messages\"<\n\x05Photo\x12\x0b\n\x03uri\x18\x01 \x01(\t\x12\x11\n\tfile_size\x18\x02 \x01(\x04\x12\x13\n\x0bs_thumbnail\x18\x03 \x01(\x0c*\x90\x02\n\tPhotoSize\x12\x12\n\x0eSize_6912_3456\x10\x00\x12\x12\n\x0eSize_6272_3136\x10\x01\x12\x12\n\x0eSize_6080_3040\x10\x02\x12\x12\n\x0eSize_4000_3000\x10\x03\x12\x12\n\x0eSize_4000_2250\x10\x04\x12\x12\n\x0eSize_5212_3542\x10\x05\x12\x12\n\x0eSize_5312_2988\x10\x06\x12\x12\n\x0eSize_8000_6000\x10\x07\x12\x12\n\x0eSize_8000_4500\x10\x08\x12\x12\n\x0eSize_2976_2976\x10\t\x12\x12\n\x0eSize_5984_5984\x10\n\x12\x13\n\x0fSize_11968_5984\x10\x0b\x12\x12\n\x0eSize_5952_2976\x10\x0c*\xbe\x01\n\x0cPhotoSubMode\x12\x10\n\x0cPHOTO_SINGLE\x10\x00\x12\r\n\tPHOTO_HDR\x10\x01\x12\x12\n\x0ePHOTO_INTERVAL\x10\x02\x12\x0f\n\x0bPHOTO_BURST\x10\x03\x12\x13\n\x0fPHOTO_AEB_NIGHT\x10\x04\x12\x14\n\x10PHOTO_INSTA_PANO\x10\x05\x12\x18\n\x14PHOTO_INSTA_PANO_HDR\x10\x06\x12\x13\n\x0fPHOTO_STARLAPSE\x10\x07\x12\x0e\n\nPHOTO_NONE\x10\x64*\xa0\x01\n\x0eRawCaptureType\x12\x18\n\x14RAW_CAPTURE_TYPE_OFF\x10\x00\x12\x18\n\x14RAW_CAPTURE_TYPE_DNG\x10\x01\x12\x18\n\x14RAW_CAPTURE_TYPE_RAW\x10\x02\x12\x1d\n\x19RAW_CAPTURE_TYPE_PURESHOT\x10\x03\x12!\n\x1dRAW_CAPTURE_TYPE_PURESHOT_RAW\x10\x04\x42\x08\xa2\x02\x05INSPBb\x06proto3'
)

_PHOTOSIZE = _descriptor.EnumDescriptor(
  name='PhotoSize',
  full_name='insta360.messages.PhotoSize',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='Size_6912_3456', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_6272_3136', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_6080_3040', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_4000_3000', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_4000_2250', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_5212_3542', index=5, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_5312_2988', index=6, number=6,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_8000_6000', index=7, number=7,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_8000_4500', index=8, number=8,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_2976_2976', index=9, number=9,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_5984_5984', index=10, number=10,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_11968_5984', index=11, number=11,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='Size_5952_2976', index=12, number=12,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=97,
  serialized_end=369,
)
_sym_db.RegisterEnumDescriptor(_PHOTOSIZE)

PhotoSize = enum_type_wrapper.EnumTypeWrapper(_PHOTOSIZE)
_PHOTOSUBMODE = _descriptor.EnumDescriptor(
  name='PhotoSubMode',
  full_name='insta360.messages.PhotoSubMode',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='PHOTO_SINGLE', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO_HDR', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO_INTERVAL', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO_BURST', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO_AEB_NIGHT', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO_INSTA_PANO', index=5, number=5,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO_INSTA_PANO_HDR', index=6, number=6,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO_STARLAPSE', index=7, number=7,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='PHOTO_NONE', index=8, number=100,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=372,
  serialized_end=562,
)
_sym_db.RegisterEnumDescriptor(_PHOTOSUBMODE)

PhotoSubMode = enum_type_wrapper.EnumTypeWrapper(_PHOTOSUBMODE)
_RAWCAPTURETYPE = _descriptor.EnumDescriptor(
  name='RawCaptureType',
  full_name='insta360.messages.RawCaptureType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='RAW_CAPTURE_TYPE_OFF', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='RAW_CAPTURE_TYPE_DNG', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='RAW_CAPTURE_TYPE_RAW', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='RAW_CAPTURE_TYPE_PURESHOT', index=3, number=3,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='RAW_CAPTURE_TYPE_PURESHOT_RAW', index=4, number=4,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=565,
  serialized_end=725,
)
_sym_db.RegisterEnumDescriptor(_RAWCAPTURETYPE)

RawCaptureType = enum_type_wrapper.EnumTypeWrapper(_RAWCAPTURETYPE)
Size_6912_3456 = 0
Size_6272_3136 = 1
Size_6080_3040 = 2
Size_4000_3000 = 3
Size_4000_2250 = 4
Size_5212_3542 = 5
Size_5312_2988 = 6
Size_8000_6000 = 7
Size_8000_4500 = 8
Size_2976_2976 = 9
Size_5984_5984 = 10
Size_11968_5984 = 11
Size_5952_2976 = 12
PHOTO_SINGLE = 0
PHOTO_HDR = 1
PHOTO_INTERVAL = 2
PHOTO_BURST = 3
PHOTO_AEB_NIGHT = 4
PHOTO_INSTA_PANO = 5
PHOTO_INSTA_PANO_HDR = 6
PHOTO_STARLAPSE = 7
PHOTO_NONE = 100
RAW_CAPTURE_TYPE_OFF = 0
RAW_CAPTURE_TYPE_DNG = 1
RAW_CAPTURE_TYPE_RAW = 2
RAW_CAPTURE_TYPE_PURESHOT = 3
RAW_CAPTURE_TYPE_PURESHOT_RAW = 4



_PHOTO = _descriptor.Descriptor(
  name='Photo',
  full_name='insta360.messages.Photo',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='uri', full_name='insta360.messages.Photo.uri', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='file_size', full_name='insta360.messages.Photo.file_size', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='s_thumbnail', full_name='insta360.messages.Photo.s_thumbnail', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
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
  serialized_start=34,
  serialized_end=94,
)

DESCRIPTOR.message_types_by_name['Photo'] = _PHOTO
DESCRIPTOR.enum_types_by_name['PhotoSize'] = _PHOTOSIZE
DESCRIPTOR.enum_types_by_name['PhotoSubMode'] = _PHOTOSUBMODE
DESCRIPTOR.enum_types_by_name['RawCaptureType'] = _RAWCAPTURETYPE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Photo = _reflection.GeneratedProtocolMessageType('Photo', (_message.Message,), {
  'DESCRIPTOR' : _PHOTO,
  '__module__' : 'photo_pb2'
  # @@protoc_insertion_point(class_scope:insta360.messages.Photo)
  })
_sym_db.RegisterMessage(Photo)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)

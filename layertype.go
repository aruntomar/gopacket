// Copyright 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"fmt"
	"strconv"
)

// LayerType is a unique identifier for each type of layer.  This enumeration
// does not match with any externally available numbering scheme... it's solely
// usable/useful within this library as a means for requesting layer types
// (see Packet.Layer) and determining which types of layers have been decoded.
// A LayerType corresponds 1:1 to a struct type.
type LayerType int64

// LayerTypeMetadata contains metadata associated with each LayerType.
type LayerTypeMetadata struct {
	// Name is the string returned by each layer type's String method.
	Name string
	// Decoder is the decoder to use when the layer type is passed in as a
	// Decoder.
	Decoder Decoder
}

type layerTypeMetadata struct {
	inUse bool
	LayerTypeMetadata
}

const maxLayerType = 2000

var ltMeta [maxLayerType]layerTypeMetadata
var ltMetaMap = map[LayerType]layerTypeMetadata{}

// RegisterLayerType creates a new layer type and registers it globally.
// The number passed in must be unique, or a runtime panic will occur.  Numbers
// 0-999 are reserved for the gopacket library.  Numbers 1000-1999 should be
// used for common application-specific types, and are very fast.  Any other
// number (negative or >= 2000) may be used for uncommon application-specific
// types, and are somewhat slower (they require a map lookup over an array
// index).
func RegisterLayerType(num int, meta LayerTypeMetadata) LayerType {
	if 0 <= num && num < maxLayerType {
		if ltMeta[num].inUse {
			panic("Layer type already exists")
		}
		ltMeta[num] = layerTypeMetadata{
			inUse:             true,
			LayerTypeMetadata: meta,
		}
	} else {
		if ltMetaMap[LayerType(num)].inUse {
			panic("Layer type already exists")
		}
		ltMetaMap[LayerType(num)] = layerTypeMetadata{
			inUse:             true,
			LayerTypeMetadata: meta,
		}
	}
	return LayerType(num)
}

// Decode decodes the given data using the decoder registered with the layer
// type.
func (t LayerType) Decode(data []byte) (_ DecodeResult, err error) {
	var d Decoder
	if 0 <= int(t) && int(t) < maxLayerType {
		d = ltMeta[int(t)].Decoder
	} else {
		d = ltMetaMap[t].Decoder
	}
	if d != nil {
		return d.Decode(data)
	}
	err = fmt.Errorf("Layer type %v has no associated decoder", t)
	return
}

// String returns the string associated with this layer type.
func (t LayerType) String() (s string) {
	if 0 <= int(t) && int(t) < maxLayerType {
		s = ltMeta[int(t)].Name
	} else {
		s = ltMetaMap[t].Name
	}
	if s == "" {
		s = strconv.Itoa(int(t))
	}
	return
}
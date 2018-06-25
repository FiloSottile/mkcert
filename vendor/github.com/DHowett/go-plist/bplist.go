package plist

type bplistTrailer struct {
	Unused            [5]uint8
	SortVersion       uint8
	OffsetIntSize     uint8
	ObjectRefSize     uint8
	NumObjects        uint64
	TopObject         uint64
	OffsetTableOffset uint64
}

const (
	bpTagNull        uint8 = 0x00
	bpTagBoolFalse         = 0x08
	bpTagBoolTrue          = 0x09
	bpTagInteger           = 0x10
	bpTagReal              = 0x20
	bpTagDate              = 0x30
	bpTagData              = 0x40
	bpTagASCIIString       = 0x50
	bpTagUTF16String       = 0x60
	bpTagUID               = 0x80
	bpTagArray             = 0xA0
	bpTagDictionary        = 0xD0
)

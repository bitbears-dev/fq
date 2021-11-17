package ogg

// https://xiph.org/ogg/doc/framing.html

import (
	"bytes"
	"fmt"

	"github.com/wader/fq/format"
	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/pkg/bitio"
	"github.com/wader/fq/pkg/decode"
)

var oggPageFormat []*decode.Format
var vorbisPacketFormat []*decode.Format
var vorbisCommentFormat []*decode.Format
var opusPacketFormat []*decode.Format
var flacMetadatablockFormat []*decode.Format
var flacFrameFormat []*decode.Format

func init() {
	registry.MustRegister(&decode.Format{
		Name:        format.OGG,
		Description: "OGG file",
		Groups:      []string{format.PROBE},
		DecodeFn:    decodeOgg,
		Dependencies: []decode.Dependency{
			{Names: []string{format.OGG_PAGE}, Formats: &oggPageFormat},
			{Names: []string{format.VORBIS_PACKET}, Formats: &vorbisPacketFormat},
			{Names: []string{format.VORBIS_COMMENT}, Formats: &vorbisCommentFormat},
			{Names: []string{format.OPUS_PACKET}, Formats: &opusPacketFormat},
			{Names: []string{format.FLAC_METADATABLOCK}, Formats: &flacMetadatablockFormat},
			{Names: []string{format.FLAC_FRAME}, Formats: &flacFrameFormat},
		},
	})
}

var (
	vorbisIdentification = []byte("\x01vorbis")
	opusIdentification   = []byte("OpusHead")
	flacIdentification   = []byte("\x7fFLAC")
)

type streamCodec int

const (
	codecUnknown streamCodec = iota
	codecVorbis
	codecOpus
	codecFlac
)

type stream struct {
	sequenceNo     uint32
	packetBuf      []byte
	packetD        *decode.D
	codec          streamCodec
	flacStreamInfo format.FlacStreamInfo
}

func decodeOgg(d *decode.D, in interface{}) interface{} {
	validPages := 0
	streams := map[uint32]*stream{}
	streamsD := d.FieldArray("streams")

	d.FieldArray("pages", func(d *decode.D) {
		for !d.End() {
			_, dv, _ := d.FieldTryFormat("page", oggPageFormat, nil)
			if dv == nil {
				break
			}
			oggPageOut, ok := dv.(format.OggPageOut)
			if !ok {
				panic("page decode is not a oggPageOut")
			}

			s, sFound := streams[oggPageOut.StreamSerialNumber]
			if !sFound {
				var packetsD *decode.D
				streamsD.FieldStruct("stream", func(d *decode.D) {
					d.FieldValueU("serial_number", uint64(oggPageOut.StreamSerialNumber))
					packetsD = d.FieldArray("packets")
				})
				s = &stream{
					sequenceNo: oggPageOut.SequenceNo,
					packetD:    packetsD,
					codec:      codecUnknown,
				}
				streams[oggPageOut.StreamSerialNumber] = s
			}

			// if !sFound && !oggPageOut.IsFirstPage {
			// 	// TODO: not first page and we haven't seen the stream before
			// 	// log.Println("not first page and we haven't seen the stream before")
			// }
			// hasData := len(s.packetBuf) > 0
			// if oggPageOut.IsContinuedPacket && !hasData {
			// 	// TODO: continuation but we haven't seen any packet data yet
			// 	// log.Println("continuation but we haven't seen any packet data yet")
			// }
			// if !oggPageOut.IsFirstPage && s.sequenceNo+1 != oggPageOut.SequenceNo {
			// 	// TODO: page gap
			// 	// log.Println("page gap")
			// }

			for _, ps := range oggPageOut.Segments {
				psBytes := ps.Len() / 8

				// TODO: cleanup
				b, _ := ps.BytesRange(0, int(psBytes))
				s.packetBuf = append(s.packetBuf, b...)
				if psBytes < 255 { // TODO: list range maps of demuxed packets?
					bb := bitio.NewBufferFromBytes(s.packetBuf, -1)

					if s.codec == codecUnknown {
						if b, err := bb.PeekBytes(len(vorbisIdentification)); err == nil && bytes.Equal(b, vorbisIdentification) {
							s.codec = codecVorbis
						} else if b, err := bb.PeekBytes(len(opusIdentification)); err == nil && bytes.Equal(b, opusIdentification) {
							s.codec = codecOpus
						} else if b, err := bb.PeekBytes(len(flacIdentification)); err == nil && bytes.Equal(b, flacIdentification) {
							s.codec = codecFlac
						}
					}

					switch s.codec {
					case codecVorbis:
						// TODO: err
						_, _, _ = s.packetD.FieldTryFormatBitBuf("packet", bb, vorbisPacketFormat, nil)
					case codecOpus:
						// TODO: err
						_, _, _ = s.packetD.FieldTryFormatBitBuf("packet", bb, opusPacketFormat, nil)
					case codecFlac:
						var firstByte byte
						bs, err := bb.PeekBytes(1)
						if err != nil {
							return
						}
						firstByte = bs[0]

						switch {
						case firstByte == 0x7f:
							s.packetD.FieldStructRootBitBufFn("packet", bb, func(d *decode.D) {
								d.FieldU8("type")
								d.FieldUTF8("signature", 4)
								d.FieldU8("major")
								d.FieldU8("minor")
								d.FieldU16("header_packets")
								d.FieldUTF8("flac_signature", 4)
								v, dv := d.FieldFormat("metadatablock", flacMetadatablockFormat, nil)
								flacMetadatablockOut, ok := dv.(format.FlacMetadatablockOut)
								if v != nil && !ok {
									panic(fmt.Sprintf("expected FlacMetadatablockOut, got %#+v", flacMetadatablockOut))
								}
								s.flacStreamInfo = flacMetadatablockOut.StreamInfo
							})
						case firstByte == 0xff:
							s.packetD.FieldFormatBitBuf("packet", bb, flacFrameFormat, nil)
						default:
							s.packetD.FieldFormatBitBuf("packet", bb, flacMetadatablockFormat, nil)

							//d.Format(flacFrame, nil)
						}
					case codecUnknown:
						s.packetD.FieldRootBitBuf("packet", bb)
					}

					s.packetBuf = nil
				}
			}

			s.sequenceNo = oggPageOut.SequenceNo
			if oggPageOut.IsLastPage {
				delete(streams, oggPageOut.StreamSerialNumber)
			}

			validPages++
		}
	})

	if validPages == 0 {
		d.Fatalf("no pages found")
	}

	return nil
}

package msg

import "reflect"

var TypeMapper = map[byte]reflect.Type{
	06: reflect.TypeFor[ServiceAccept](),
	20: reflect.TypeFor[KexInit](),
	21: reflect.TypeFor[Msg](),
	31: reflect.TypeFor[KexReply](),
	52: reflect.TypeFor[Msg](),
	53: reflect.TypeFor[UserAuthBanner](),
	80: reflect.TypeFor[Request](),
	90: reflect.TypeFor[ChannelOpen](),
	91: reflect.TypeFor[ChannelOpenConfirm](),
	93: reflect.TypeFor[ChannelWindowAdjust](),
	94: reflect.TypeFor[ChannelData](),
	95: reflect.TypeFor[ChannelDataExtended](),
}

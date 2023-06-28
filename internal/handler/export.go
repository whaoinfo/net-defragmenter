package handler

import "github.com/whaoinfo/net-defragmenter/definition"

var (
	handlerMap = map[definition.FragmentType]IHandler{
		definition.IPV6FragType: &IPV6Handler{},
	}
)

func GetHandler(fragType definition.FragmentType) IHandler {
	return handlerMap[fragType]
}

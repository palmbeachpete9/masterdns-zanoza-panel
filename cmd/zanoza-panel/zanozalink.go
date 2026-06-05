package main

import (
	"encoding/base64"
	"encoding/json"
)

// sharedProfilePayload mirrors Zanoza iOS app's ProfileShareCodec
// SharedProfilePayload (version 1). Field names and JSON shape must match
// so the app's importer accepts the link verbatim.
type sharedProfilePayload struct {
	Version                     int    `json:"version"`
	Name                        string `json:"name"`
	Domain                      string `json:"domain"`
	EncryptionKey               string `json:"encryptionKey"`
	EncryptionMethod            int    `json:"encryptionMethod"`
	UploadCompression           int    `json:"uploadCompression"`
	DownloadCompression         int    `json:"downloadCompression"`
	PacketDuplicationCount      int    `json:"packetDuplicationCount"`
	SetupPacketDuplicationCount int    `json:"setupPacketDuplicationCount"`
	ResolverBalancingStrategy   int    `json:"resolverBalancingStrategy"`
	LogLevel                    string `json:"logLevel"`
}

// zanozaLink builds a zanoza://profile?data=<base64url-json> sharing link
// for the given instance, using sensible client-side defaults.
func zanozaLink(inst Instance) string {
	name := inst.Label
	if name == "" {
		name = inst.Domain
	}
	payload := sharedProfilePayload{
		Version:                     1,
		Name:                        name,
		Domain:                      inst.Domain,
		EncryptionKey:               inst.Key,
		EncryptionMethod:            inst.Method,
		UploadCompression:           0, // off
		DownloadCompression:         0, // off
		PacketDuplicationCount:      3,
		SetupPacketDuplicationCount: 4,
		ResolverBalancingStrategy:   3, // Least Loss
		LogLevel:                    "INFO",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return "zanoza://profile?data=" + encoded
}

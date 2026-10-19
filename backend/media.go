package main

import (
	"bytes"
	"context"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	_ "golang.org/x/image/webp"
)

func decodeQRImages(images [][]byte) []string {
	var out []string
	hints := map[gozxing.DecodeHintType]interface{}{gozxing.DecodeHintType_TRY_HARDER: true}
	for _, data := range images {
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			continue // unreadable image: Gemini still sees it
		}
		bmp, err := gozxing.NewBinaryBitmapFromImage(img)
		if err != nil {
			continue
		}
		res, err := qrcode.NewQRCodeReader().Decode(bmp, hints)
		if err == nil && res.GetText() != "" {
			out = append(out, res.GetText())
		}
	}
	return out
}

// Formats Gemini reads directly; anything else goes through ffmpeg.
var geminiAudio = set("audio/wav", "audio/x-wav", "audio/mp3", "audio/mpeg", "audio/aac", "audio/ogg", "audio/flac", "audio/aiff")

// toGeminiAudio converts phone/browser formats (m4a, amr, webm, 3gp) to mp3 in a temp dir that is always removed.
func toGeminiAudio(ctx context.Context, data []byte, mime, filename string) Media {
	if geminiAudio[mime] {
		if mime == "audio/mp3" {
			mime = "audio/mpeg"
		}
		return Media{data, mime}
	}
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		return Media{data, mime}
	}
	dir, err := os.MkdirTemp("", "dhaal-audio-")
	if err != nil {
		return Media{data, mime}
	}
	defer os.RemoveAll(dir)
	ext := filepath.Ext(filename)
	if ext == "" {
		ext = ".bin"
	}
	src, dst := filepath.Join(dir, "in"+ext), filepath.Join(dir, "out.mp3")
	if os.WriteFile(src, data, 0o600) != nil {
		return Media{data, mime}
	}
	cmd := exec.CommandContext(ctx, ffmpeg, "-y", "-loglevel", "error", "-i", src, "-ac", "1", "-ar", "16000", "-b:a", "48k", dst)
	if cmd.Run() != nil {
		return Media{data, mime}
	}
	out, err := os.ReadFile(dst)
	if err != nil {
		return Media{data, mime}
	}
	return Media{out, "audio/mpeg"}
}

func itoa(n int) string { return strconv.Itoa(n) }

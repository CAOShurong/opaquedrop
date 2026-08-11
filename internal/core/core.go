package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/CAOShurong/opaquedrop/internal/model"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{20,32}$`)

func RandomToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func ValidID(id string) bool { return idPattern.MatchString(id) }

func MakeRequest(baseURL, label string, createdAt, expiresAt time.Time, maxFiles int, maxBytes int64, deleteAfterCollect bool) (model.RequestBundle, model.KeyFile, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return model.RequestBundle{}, model.KeyFile{}, errors.New("base URL must be an absolute http or https URL")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "[::1]")) {
		return model.RequestBundle{}, model.KeyFile{}, errors.New("base URL must use HTTPS (HTTP is allowed only for localhost)")
	}
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 120 {
		return model.RequestBundle{}, model.KeyFile{}, errors.New("label must contain 1 to 120 characters")
	}
	if !expiresAt.After(createdAt) {
		return model.RequestBundle{}, model.KeyFile{}, errors.New("expiration must be in the future")
	}
	if maxFiles < 1 || maxFiles > 10_000 {
		return model.RequestBundle{}, model.KeyFile{}, errors.New("max files must be between 1 and 10000")
	}
	if maxBytes < 1 || maxBytes > 1<<50 {
		return model.RequestBundle{}, model.KeyFile{}, errors.New("max bytes must be between 1 byte and 1 PiB")
	}

	id, err := RandomToken(16)
	if err != nil {
		return model.RequestBundle{}, model.KeyFile{}, err
	}
	submitToken, err := RandomToken(32)
	if err != nil {
		return model.RequestBundle{}, model.KeyFile{}, err
	}
	collectToken, err := RandomToken(32)
	if err != nil {
		return model.RequestBundle{}, model.KeyFile{}, err
	}
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return model.RequestBundle{}, model.KeyFile{}, err
	}
	publicKey := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())

	bundle := model.RequestBundle{
		SchemaVersion: model.SchemaVersion, ID: id, Label: label,
		CreatedAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(), MaxFiles: maxFiles, MaxBytes: maxBytes,
		DeleteAfterCollect: deleteAfterCollect, PublicKey: publicKey,
		SubmitTokenHash: HashToken(submitToken), CollectTokenHash: HashToken(collectToken),
	}
	submitURL := fmt.Sprintf("%s/r/%s#t=%s", baseURL, id, url.QueryEscape(submitToken))
	key := model.KeyFile{
		SchemaVersion: model.SchemaVersion, RequestID: id, Label: label,
		CreatedAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(), ServerURL: baseURL,
		SubmitURL: submitURL, CollectToken: collectToken,
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey.Bytes()), PublicKey: publicKey,
	}
	return bundle, key, nil
}

func ParseBytes(value string) (int64, error) {
	s := strings.TrimSpace(strings.ToUpper(value))
	re := regexp.MustCompile(`^([0-9]+)\s*(B|KB|KIB|MB|MIB|GB|GIB|TB|TIB)?$`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid byte size %q", value)
	}
	var n int64
	if _, err := fmt.Sscanf(m[1], "%d", &n); err != nil {
		return 0, err
	}
	multipliers := map[string]int64{"": 1, "B": 1, "KB": 1000, "KIB": 1 << 10, "MB": 1000 * 1000, "MIB": 1 << 20, "GB": 1000 * 1000 * 1000, "GIB": 1 << 30, "TB": 1000 * 1000 * 1000 * 1000, "TIB": 1 << 40}
	mul := multipliers[m[2]]
	if n <= 0 || n > (1<<62)/mul {
		return 0, errors.New("byte size is out of range")
	}
	return n * mul, nil
}

func SafeFilename(name string) string {
	name = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(name, "\\", "/"), "\x00", ""))
	name = filepath.Base(name)
	name = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`).ReplaceAllString(name, "_")
	name = strings.Trim(name, " .")
	if name == "" || name == "." || name == ".." {
		name = "received-file"
	}
	if windowsDeviceName(name) {
		name = "_" + name
	}
	return truncateFilenameComponent(name)
}

const (
	maxFilenameBytes      = 240
	maxFilenameUTF16Units = 240
	maxExtensionBytes     = 40
	maxExtensionUTF16     = 40
)

func windowsDeviceName(name string) bool {
	stem := name
	if dot := strings.IndexByte(stem, '.'); dot >= 0 {
		stem = stem[:dot]
	}
	stem = strings.ToUpper(strings.TrimRight(stem, " ."))
	if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" {
		return true
	}
	runes := []rune(stem)
	if len(runes) != 4 || (!strings.HasPrefix(stem, "COM") && !strings.HasPrefix(stem, "LPT")) {
		return false
	}
	return (runes[3] >= '1' && runes[3] <= '9') || runes[3] == '\u00b9' || runes[3] == '\u00b2' || runes[3] == '\u00b3'
}

func truncateFilenameComponent(name string) string {
	extension := filepath.Ext(name)
	if extension == name {
		extension = ""
	}
	stem := strings.TrimSuffix(name, extension)
	extension = truncateUnits(extension, maxExtensionBytes, maxExtensionUTF16)
	stem = truncateUnits(stem, maxFilenameBytes-len([]byte(extension)), maxFilenameUTF16Units-utf16Units(extension))
	if stem == "" {
		stem = truncateUnits("received-file", maxFilenameBytes-len([]byte(extension)), maxFilenameUTF16Units-utf16Units(extension))
	}
	return stem + extension
}

func truncateUnits(value string, maxBytes, maxUTF16 int) string {
	bytesUsed := 0
	unitsUsed := 0
	end := 0
	for offset, r := range value {
		byteCount := len(string(r))
		unitCount := 1
		if r > 0xffff {
			unitCount = 2
		}
		if bytesUsed+byteCount > maxBytes || unitsUsed+unitCount > maxUTF16 {
			break
		}
		bytesUsed += byteCount
		unitsUsed += unitCount
		end = offset + byteCount
	}
	return value[:end]
}

func utf16Units(value string) int {
	units := 0
	for _, r := range value {
		units++
		if r > 0xffff {
			units++
		}
	}
	return units
}

func MarshalPretty(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

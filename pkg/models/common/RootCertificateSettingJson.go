package cm

type RootCertificateSettingJson struct {
	Name              string  `json:"name"`
	KeyType           KeyType `json:"keyType"`
	KeySize           int     `json:"keySize"`
	FingerprintSha256 string  `json:"SHA256"`
	TimeValidUntil    string  `json:"timeValidUntil"`
	URL               string  `json:"URL"`
	FilePath          string  `json:"filePath"`
}

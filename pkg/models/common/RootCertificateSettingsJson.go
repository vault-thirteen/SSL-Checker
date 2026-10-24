package cm

type RootCertificateSettingsJson struct {
	PoolName string                       `json:"poolName"`
	Keys     []RootCertificateSettingJson `json:"keys"`
}

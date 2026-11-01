package control

import (
	"errors"
	"os"

	"github.com/pelletier/go-toml/v2"
	"github.com/xjdrew/kone/pkg/kone"
)

// Only persisted managed profiles may discard the retired HTTP-manager option.
// File-mode configs and new API writes remain strict. Retain the complete
// original document before any later explicit save normalizes the TOML.
func readProfileConfig(path string, original, configuration []byte) (*kone.KoneConfig, error) {
	cfg, err := kone.ParseManagedConfig(configuration)
	if err == nil {
		return cfg, nil
	}
	var value map[string]any
	if toml.Unmarshal(configuration, &value) != nil {
		return nil, err
	}
	general, ok := value["general"].(map[string]any)
	if !ok {
		return nil, err
	}
	legacy, exists := general["manager-addr"]
	if !exists {
		return nil, err
	}
	if _, ok := legacy.(string); !ok {
		return nil, errors.New("saved legacy manager address is invalid")
	}
	delete(general, "manager-addr")
	data, marshalErr := toml.Marshal(value)
	if marshalErr != nil {
		return nil, marshalErr
	}
	cfg, err = kone.ParseManagedConfig(data)
	if err != nil {
		return nil, err
	}
	backup, err := os.OpenFile(path+".legacy-manager", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, errors.New("cannot preserve legacy settings backup")
	}
	_, err = backup.Write(original)
	if err == nil {
		err = backup.Sync()
	}
	closeErr := backup.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path + ".legacy-manager")
		return nil, errors.New("cannot preserve legacy settings backup")
	}
	return cfg, nil
}

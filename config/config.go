package config

import (
	"KeyChain-CLI/logger"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type ContextKey uint

const ViperKey ContextKey = 0

func LoadYamlConfig(log logger.Logger) (*viper.Viper, error) {
	localViper := viper.New()
	localViper.SetConfigName("config")
	localViper.SetConfigType("yaml")
	localViper.AddConfigPath(".")

	err := localViper.ReadInConfig()
	if err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			log.Warn("конфиг не найден, используются параметры CLI или дефолтные значения")
			return localViper, nil
		}

		return nil, fmt.Errorf("ошибка чтения конфига: %w", err)
	}

	log.Info("конфиг загружен: ", localViper.ConfigFileUsed())

	return localViper, nil
}

func BindFlags(cmd *cobra.Command, v *viper.Viper, log logger.Logger) error {
	var errs []error

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if err := v.BindPFlag(flag.Name, flag); err != nil {
			e := fmt.Errorf("ошибка привязки флага '%s': %w", flag.Name, err)
			errs = append(errs, e)
			log.Warn(e)
		}

		if !flag.Changed && v.IsSet(flag.Name) {
			if err := cmd.Flags().Set(flag.Name, v.GetString(flag.Name)); err != nil {
				e := fmt.Errorf("ошибка установки флага '%s' из конфига: %w", flag.Name, err)
				errs = append(errs, e)
				log.Warn(e)
			}
		}
	})

	return errors.Join(errs...) // не теряем все ошибки, собираем все ошибки
}

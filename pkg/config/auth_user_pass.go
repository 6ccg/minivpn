package config

import "fmt"

// AuthUserPassSetup returns the username/password to include in key-method-2 control messages.
func (o *OpenVPNOptions) AuthUserPassSetup() (string, string, error) {
	// Prefer the currently configured values (e.g., injected/overridden by the caller).
	if o.Username != "" && o.Password != "" {
		if o.AuthNoCache {
			o.authUserPassSourceUsername = ""
			o.authUserPassSourcePassword = ""
		} else {
			o.authUserPassSourceUsername = o.Username
			o.authUserPassSourcePassword = o.Password
		}
		return o.Username, o.Password, nil
	}

	if o.AuthNoCache {
		if o.AuthUserPass {
			return "", "", fmt.Errorf("%w: %s", ErrBadConfig, "auth-user-pass requires username and password")
		}
		return "", "", nil
	}

	// Fall back to the last known source values (OpenVPN's auth_user_pass_setup analogue).
	if o.authUserPassSourceUsername != "" && o.authUserPassSourcePassword != "" {
		return o.authUserPassSourceUsername, o.authUserPassSourcePassword, nil
	}

	if o.AuthUserPass {
		return "", "", fmt.Errorf("%w: %s", ErrBadConfig, "auth-user-pass requires username and password")
	}
	return "", "", nil
}

// PurgeAuthUserPass purges cached Username/Password when --auth-nocache is set.
func (o *OpenVPNOptions) PurgeAuthUserPass() {
	if !o.AuthNoCache {
		return
	}
	o.Username = ""
	o.Password = ""
	o.authUserPassSourceUsername = ""
	o.authUserPassSourcePassword = ""
}

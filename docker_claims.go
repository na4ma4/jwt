package jwt

const (
	// DockerResourceActionType is a docker resource action.
	DockerResourceActionType ClaimType = 255
)

// DockerResourceActions stores allowed actions on a named and typed resource.
type DockerResourceActions struct {
	Type    string   `json:"type"`
	Class   string   `json:"class,omitempty"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// DockerResourceAction constructs a field with the given key and value.
func DockerResourceAction(key string, action *DockerResourceActions) Claim {
	return Claim{
		Key:       key,
		Type:      DockerResourceActionType,
		Interface: action,
	}
}

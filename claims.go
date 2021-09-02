package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	pascaljwt "github.com/pascaldekloe/jwt"
	uuid "github.com/satori/go.uuid"
)

// ErrInvalidClaimType is returned when an operation tries to return an invalid claim type.
var ErrInvalidClaimType = errors.New("invalid claim type")

const (
	// Issuer is the IANA Registered claim for JWT issuer.
	Issuer string = "iss"
	// Subject is the IANA Registered claim for JWT subject.
	Subject string = "sub"
	// Audience is the IANA Registered claim for JWT audience.
	Audience string = "aud"
	// Expires is the IANA Registered claim for JWT expiry time.
	Expires string = "exp"
	// NotBefore is the IANA Registered claim for JWT not before time.
	NotBefore string = "nbf"
	// Issued is the IANA Registered claim for JWT issue time.
	Issued string = "iat"
	// ID is the IANA Registered claim for JWT ID.
	ID string = "jti"
)

// A ClaimType indicates which member of the Field union struct should be used
// and how it should be serialized.
type ClaimType uint8

// Type list borrowed from uber-go/zap.
const (
	// UnknownType is the default, this will throw an error.
	UnknownType ClaimType = iota
	// ArrayMarshalerType indicates that the field carries an ArrayMarshaler.
	ArrayMarshalerType
	// ObjectMarshalerType indicates that the field carries an ObjectMarshaler.
	ObjectMarshalerType
	// BinaryType indicates that the field carries an opaque binary blob.
	BinaryType
	// BoolType indicates that the field carries a bool.
	BoolType
	// ByteStringType indicates that the field carries UTF-8 encoded bytes.
	ByteStringType
	// Complex128Type indicates that the field carries a complex128.
	Complex128Type
	// Complex64Type indicates that the field carries a complex128.
	Complex64Type
	// DurationType indicates that the field carries a time.Duration.
	DurationType
	// Float64Type indicates that the field carries a float64.
	Float64Type
	// Float32Type indicates that the field carries a float32.
	Float32Type
	// Int64Type indicates that the field carries an int64.
	Int64Type
	// Int32Type indicates that the field carries an int32.
	Int32Type
	// Int16Type indicates that the field carries an int16.
	Int16Type
	// Int8Type indicates that the field carries an int8.
	Int8Type
	// StringType indicates that the field carries a string.
	StringType
	// StringsType indicates that the field carries a string slice.
	StringsType
	// TimeType indicates that the field carries a time.Time.
	TimeType
	// Uint64Type indicates that the field carries a uint64.
	Uint64Type
	// Uint32Type indicates that the field carries a uint32.
	Uint32Type
	// Uint16Type indicates that the field carries a uint16.
	Uint16Type
	// Uint8Type indicates that the field carries a uint8.
	Uint8Type
	// UintptrType indicates that the field carries a uintptr.
	UintptrType
	// ReflectType indicates that the field carries an interface{}, which should
	// be serialized using reflection.
	ReflectType
	// NamespaceType signals the beginning of an isolated namespace. All
	// subsequent fields should be added to the new namespace.
	NamespaceType
	// StringerType indicates that the field carries a fmt.Stringer.
	StringerType
	// ErrorType indicates that the field carries an error.
	ErrorType
	// SkipType indicates that the field is a no-op.
	SkipType
)

// // Claims is JWT payload representation relayed from `pascaljwt.Claims`.
// type Claims pascaljwt.Claims

// A Claim is a marshaling operation used to add a key-value pair to a tokens
// context. Most claims are lazily marshaled, so it's inexpensive to add claims
// to disabled debug-level log statements.
type Claim struct {
	Key       string
	Type      ClaimType
	Integer   int64
	String    string
	Interface interface{}
}

// IsRegistered returns true if the Key is a IANA registered "JSON Web Token Claims".
func (c *Claim) IsRegistered() bool {
	switch strings.ToLower(c.Key) {
	case "issuer", Issuer,
		"subject", Subject,
		"audience", Audience,
		"expires", Expires,
		"notbefore", NotBefore,
		"issued", Issued,
		"id", ID:
		return true
	default:
		return false
	}
}

// Field returns the JWT compatible field from some useful longer names.
func (c *Claim) Field() string {
	switch strings.ToLower(c.Key) {
	case "issuer", Issuer:
		return Issuer
	case "subject", Subject:
		return Subject
	case "audience", Audience:
		return Audience
	case "expires", Expires:
		return Expires
	case "notbefore", NotBefore:
		return NotBefore
	case "issued", Issued:
		return Issued
	case "id", ID:
		return ID
	default:
		return c.Key
	}
}

// Time returns the time value of the `Field` or an error if it is not a `TimeType`.
func (c *Claim) Time() (time.Time, error) {
	if c.Type == TimeType {
		t := time.Unix(0, c.Integer)

		return t, nil
	}

	return time.Time{}, ErrInvalidClaimType
}

// String constructs a field with the given key and value.
func String(key, val string) Claim {
	return Claim{Key: key, Type: StringType, String: val}
}

// Strings constructs a field with the given key and value.
func Strings(key string, val []string) Claim {
	return Claim{Key: key, Type: StringsType, Interface: val}
}

// Time constructs a field with the given key and value.
func Time(key string, val time.Time) Claim {
	return Claim{
		Key:     key,
		Type:    TimeType,
		Integer: val.UnixNano(),
		// Interface: val.Location(),
	}
}

// Int constructs a field with the given key and value.
func Int(key string, val int) Claim {
	return Int64(key, int64(val))
}

// Int64 constructs a field with the given key and value.
func Int64(key string, val int64) Claim {
	return Claim{Key: key, Type: Int64Type, Integer: val}
}

// Bool constructs a field with the given key and value.
func Bool(key string, val bool) Claim {
	return Claim{Key: key, Type: BoolType, Interface: val}
}

// Reflect constructs a field with the given key and an arbitrary object. It uses
// an encoding-appropriate, reflection-based function to lazily serialize nearly
// any object into the logging context, but it's relatively slow and
// allocation-heavy. Outside tests, Any is always a better choice.
//
// If encoding fails (e.g., trying to serialize a map[int]string to JSON), Reflect
// includes the error message in the final log output.
func Reflect(key string, val interface{}) Claim {
	return Claim{Key: key, Type: ReflectType, Interface: val}
}

// Any takes a key and an arbitrary value and chooses the best way to represent
// them as a field, falling back to a reflection-based approach only if
// necessary.
//
// Since byte/uint8 and rune/int32 are aliases, Any can't differentiate between
// them. To minimize surprises, []byte values are treated as binary blobs, byte
// values are treated as uint8, and runes are always treated as integers.
//
func Any(key string, value interface{}) Claim {
	switch val := value.(type) {
	case bool:
		return Bool(key, val)
	case int:
		return Int(key, val)
	case int64:
		return Int64(key, val)
	case string:
		return String(key, val)
	case []string:
		return Strings(key, val)
	case time.Time:
		return Time(key, val)
	// case []time.Time:
	// 	return Times(key, val)
	// case time.Duration:
	// 	return Duration(key, val)
	// case []time.Duration:
	// 	return Durations(key, val)
	// case error:
	// 	return NamedError(key, val)
	// case []error:
	// 	return Errors(key, val)
	// case fmt.Stringer:
	// 	return Stringer(key, val)
	default:
		return Reflect(key, val)
	}
}

// ConstructClaimsFromSlice takes a slice of `Claim`s and returns a prepared
// `pascaljwt.Claims` pointer, or an error if construction failed.
func ConstructClaimsFromSlice(claims ...Claim) (*pascaljwt.Claims, error) {
	tokenClaims := &pascaljwt.Claims{
		Registered: pascaljwt.Registered{},
		Set:        map[string]interface{}{},
	}

	for _, claim := range claims {
		if claim.IsRegistered() {
			err := constructRegisteredClaim(tokenClaims, claim)
			if err != nil {
				return nil, err
			}
		} else {
			err := constructUnregisteredClaim(tokenClaims, claim)
			if err != nil {
				return nil, err
			}
		}
	}

	if tokenClaims.ID == "" {
		tokenClaims.ID = uuid.Must(uuid.NewV4()).String()
	}

	return tokenClaims, nil
}

// ErrInvalidTypeForClaim is returned when a registered claim is using an invalid type.
var ErrInvalidTypeForClaim = errors.New("invalid type for registered claim")

// constructRegisteredClaim adds IANA registered `Claim` fields to the supplied `jwt.Claims`.
//nolint:cyclop
func constructRegisteredClaim(tokenClaims *pascaljwt.Claims, claim Claim) error {
	switch claim.Field() {
	case Issuer:
		tokenClaims.Registered.Issuer = claim.String
	case Subject:
		tokenClaims.Registered.Subject = claim.String
	case Audience:
		if v, ok := claim.Interface.([]string); ok {
			tokenClaims.Registered.Audiences = v
		}
	case Expires:
		if claim.Type == TimeType {
			t, err := claim.Time()
			if err != nil {
				return fmt.Errorf("%w for exp", err)
			}

			tokenClaims.Registered.Expires = pascaljwt.NewNumericTime(t)
		} else {
			return fmt.Errorf("%w for exp", ErrInvalidTypeForClaim)
		}
	case NotBefore:
		if claim.Type == TimeType {
			t, err := claim.Time()
			if err != nil {
				return fmt.Errorf("%w for nbf", err)
			}

			tokenClaims.Registered.NotBefore = pascaljwt.NewNumericTime(t)
		} else {
			return fmt.Errorf("%w for nbf", ErrInvalidTypeForClaim)
		}
	case Issued:
		if claim.Type == TimeType {
			t, err := claim.Time()
			if err != nil {
				return fmt.Errorf("%w for iat", err)
			}

			tokenClaims.Registered.Issued = pascaljwt.NewNumericTime(t)
		} else {
			return fmt.Errorf("%w for iat", ErrInvalidTypeForClaim)
		}
	case ID:
		tokenClaims.Registered.ID = claim.String
	}

	return nil
}

// ErrUnsupportedClaimType is returned when an unsupported claim type is used.
var ErrUnsupportedClaimType = errors.New("unsupported claim type")

// ErrClaimFormatInvalid is returned when a claim format is invalid.
var ErrClaimFormatInvalid = errors.New("claim format is invalid")

// constructRegisteredClaim adds unregistered `Claim` fields to the supplied `pascaljwt.Claims`.
//nolint:cyclop
func constructUnregisteredClaim(tokenClaims *pascaljwt.Claims, claim Claim) error {
	switch claim.Type {
	case ArrayMarshalerType, BinaryType, ByteStringType, Complex128Type, Complex64Type, DurationType,
		ErrorType, Float32Type, Float64Type, NamespaceType, ObjectMarshalerType, ReflectType, SkipType,
		StringerType, Uint16Type, Uint32Type, Uint64Type, Uint8Type, UintptrType, UnknownType:
		return fmt.Errorf("%w: %d", ErrUnsupportedClaimType, claim.Type)
	case Int8Type, Int16Type, Int32Type, Int64Type:
		tokenClaims.Set[claim.Key] = claim.Integer
	case StringType:
		tokenClaims.Set[claim.Key] = claim.String
	case StringsType:
		if v, ok := claim.Interface.([]string); ok {
			tokenClaims.Set[claim.Key] = v
		} else {
			return fmt.Errorf("%w []string claim type: %s", ErrClaimFormatInvalid, claim.Key)
		}
	case BoolType:
		if b, ok := claim.Interface.(bool); ok {
			tokenClaims.Set[claim.Key] = b
		} else {
			return fmt.Errorf("%w bool claim type: %s", ErrClaimFormatInvalid, claim.Key)
		}
	case TimeType:
		t, err := claim.Time()
		if err != nil {
			return fmt.Errorf("%w for %s", err, claim.Key)
		}

		tokenClaims.Set[claim.Key] = pascaljwt.NewNumericTime(t)
	default:
		return fmt.Errorf("%w: %d", ErrUnsupportedClaimType, claim.Type)
	}

	return nil
}

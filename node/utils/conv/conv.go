package conv

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/trufnetwork/kwil-db/core/types"
)

func String(a any) (string, error) {
	switch xt := a.(type) {
	case string:
		return xt, nil
	case fmt.Stringer:
		return xt.String(), nil
	case int:
		return signedIntToStr(xt), nil
	case int8:
		return signedIntToStr(xt), nil
	case int16:
		return signedIntToStr(xt), nil
	case int32:
		return signedIntToStr(xt), nil
	case int64:
		return signedIntToStr(xt), nil
	case uint:
		return unsignedIntToStr(xt), nil
	case uint8:
		return unsignedIntToStr(xt), nil
	case uint16:
		return unsignedIntToStr(xt), nil
	case uint32:
		return unsignedIntToStr(xt), nil
	case uint64:
		return unsignedIntToStr(xt), nil
	case uintptr:
		return unsignedIntToStr(xt), nil
	case float32:
		return strconv.FormatFloat(float64(xt), 'f', -1, 32), nil
	case float64:
		return strconv.FormatFloat(xt, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(xt), nil
	case []byte:
		if utf8.Valid(xt) {
			return string(xt), nil
		} else {
			return "", errors.New("cannot convert invalid utf8 []byte to string")
		}
	}
	return "", fmt.Errorf("cannot convert %T to string", a)
}

func signedIntToStr[T signedInts](val T) string {
	return strconv.FormatInt(int64(val), 10)
}

func unsignedIntToStr[T unsignedInts](val T) string {
	return strconv.FormatUint(uint64(val), 10)
}

type signedInts interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type unsignedInts interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

func Int(a any) (int64, error) {
	switch a := a.(type) {
	case int:
		return int64(a), nil
	case int8:
		return int64(a), nil
	case int16:
		return int64(a), nil
	case int32:
		return int64(a), nil
	case int64:
		return a, nil
	case uint:
		return int64(a), nil
	case uint8:
		return int64(a), nil
	case uint16:
		return int64(a), nil
	case uint32:
		return int64(a), nil
	case uint64:
		return int64(a), nil
	case bool:
		if a {
			return 1, nil
		}
		return 0, nil
	case string:
		i, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return 0, err
		}

		return i, nil
	case float32:
		return int64(a), nil
	case float64:
		return int64(a), nil
	case []byte:
		return strconv.ParseInt(string(a), 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to int", a)
	}
}

func Bool(a any) (bool, error) {
	switch a := a.(type) {
	case bool:
		return a, nil
	case int:
		return a != 0, nil
	case int8:
		return a != 0, nil
	case int16:
		return a != 0, nil
	case int32:
		return a != 0, nil
	case int64:
		return a != 0, nil
	case uint:
		return a != 0, nil
	case uint8:
		return a != 0, nil
	case uint16:
		return a != 0, nil
	case uint32:
		return a != 0, nil
	case uint64:
		return a != 0, nil
	case string:
		return strconv.ParseBool(a)
	case float32:
		return a != 0, nil
	case float64:
		return a != 0, nil
	case []byte:
		return strconv.ParseBool(string(a))
	}
	return false, fmt.Errorf("cannot convert %T to bool", a)
}

func Blob(a any) ([]byte, error) {
	switch a := a.(type) {
	case []byte:
		return a, nil
	case string:
		return []byte(a), nil
	case int:
		return []byte(strconv.FormatInt(int64(a), 10)), nil
	case int8:
		return []byte(strconv.FormatInt(int64(a), 10)), nil
	case int16:
		return []byte(strconv.FormatInt(int64(a), 10)), nil
	case int32:
		return []byte(strconv.FormatInt(int64(a), 10)), nil
	case int64:
		return []byte(strconv.FormatInt(a, 10)), nil
	case uint:
		return []byte(strconv.FormatUint(uint64(a), 10)), nil
	case uint8:
		return []byte(strconv.FormatUint(uint64(a), 10)), nil
	case uint16:
		return []byte(strconv.FormatUint(uint64(a), 10)), nil
	case uint32:
		return []byte(strconv.FormatUint(uint64(a), 10)), nil
	case uint64:
		return []byte(strconv.FormatUint(a, 10)), nil
	case bool:
		return []byte(strconv.FormatBool(a)), nil
	case *types.UUID:
		return a[:], nil
	}

	return nil, fmt.Errorf("cannot convert %T to []byte", a)
}

// UUID converts a value to a UUID.
func UUID(a any) (*types.UUID, error) {
	switch a := a.(type) {
	case *types.UUID:
		return a, nil
	case []byte:
		if len(a) != 16 {
			// go to default case
			break
		}

		uuid := types.UUID{}
		copy(uuid[:], a)

		return &uuid, nil
	}

	str, err := String(a)
	if err != nil {
		return nil, err
	}

	return types.ParseUUID(str)
}

// Decimal converts a value to a Decimal.
func Decimal(a any) (*types.Decimal, error) {
	switch a := a.(type) {
	case *types.Decimal:
		return a, nil
	case string:
		return types.ParseDecimal(a)
	case int, int8, int16, int32, int64:
		return types.ParseDecimal(fmt.Sprint(a))
	case fmt.Stringer:
		return types.ParseDecimal(a.String())
	case nil:
		// return decimal.NewFromBigInt(big.NewInt(0), 0)
		return types.ParseDecimal("0")
	}

	str, err := String(a)
	if err != nil {
		return nil, err
	}

	return types.ParseDecimal(str)
}

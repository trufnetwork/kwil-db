// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package abigen

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// ITrufNetworkBridgeSignature is an auto generated low-level Go binding around an user-defined struct.
type ITrufNetworkBridgeSignature struct {
	V uint8
	R [32]byte
	S [32]byte
}

// TrufNetworkBridgeMetaData contains all meta data concerning the TrufNetworkBridge contract.
var TrufNetworkBridgeMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"UPGRADE_INTERFACE_VERSION\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"acceptOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"deposit\",\"inputs\":[{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"recipient\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"getBridgedToken\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getRequiredSigners\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getSignerStatus\",\"inputs\":[{\"name\":\"signer\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"initialize\",\"inputs\":[{\"name\":\"_owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_bridgedToken\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"pendingOwner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"proxiableUUID\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"rewardToken\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"setRequiredSigners\",\"inputs\":[{\"name\":\"requiredSigners\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setSigner\",\"inputs\":[{\"name\":\"signer\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"isSigner\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"upgradeToAndCall\",\"inputs\":[{\"name\":\"newImplementation\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"withdraw\",\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"kwilBlockHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"root\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"proof\",\"type\":\"bytes32[]\",\"internalType\":\"bytes32[]\"},{\"name\":\"signatures\",\"type\":\"tuple[]\",\"internalType\":\"structITrufNetworkBridge.Signature[]\",\"components\":[{\"name\":\"v\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"r\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"s\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"event\",\"name\":\"Deposit\",\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferStarted\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RequiredSignersSet\",\"inputs\":[{\"name\":\"requiredSigners\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"SignerSet\",\"inputs\":[{\"name\":\"signer\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"isSigner\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Upgraded\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Withdraw\",\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"kwilBlockHash\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AddressEmptyCode\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"AlreadyProcessed\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ECDSAInvalidSignature\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ECDSAInvalidSignatureLength\",\"inputs\":[{\"name\":\"length\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"ECDSAInvalidSignatureS\",\"inputs\":[{\"name\":\"s\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"ERC1967InvalidImplementation\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC1967NonPayable\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"FailedCall\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidDepositAmount\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidInitialization\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidMerkleProof\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidSignatures\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidUpgrade\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotInitializing\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"OwnableInvalidOwner\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"OwnableUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"SafeERC20FailedOperation\",\"inputs\":[{\"name\":\"token\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"UUPSUnauthorizedCallContext\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"UUPSUnsupportedProxiableUUID\",\"inputs\":[{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"ZeroAddress\",\"inputs\":[]}]",
}

// TrufNetworkBridgeABI is the input ABI used to generate the binding from.
// Deprecated: Use TrufNetworkBridgeMetaData.ABI instead.
var TrufNetworkBridgeABI = TrufNetworkBridgeMetaData.ABI

// TrufNetworkBridge is an auto generated Go binding around an Ethereum contract.
type TrufNetworkBridge struct {
	TrufNetworkBridgeCaller     // Read-only binding to the contract
	TrufNetworkBridgeTransactor // Write-only binding to the contract
	TrufNetworkBridgeFilterer   // Log filterer for contract events
}

// TrufNetworkBridgeCaller is an auto generated read-only Go binding around an Ethereum contract.
type TrufNetworkBridgeCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TrufNetworkBridgeTransactor is an auto generated write-only Go binding around an Ethereum contract.
type TrufNetworkBridgeTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TrufNetworkBridgeFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type TrufNetworkBridgeFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// TrufNetworkBridgeSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type TrufNetworkBridgeSession struct {
	Contract     *TrufNetworkBridge // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// TrufNetworkBridgeCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type TrufNetworkBridgeCallerSession struct {
	Contract *TrufNetworkBridgeCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// TrufNetworkBridgeTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type TrufNetworkBridgeTransactorSession struct {
	Contract     *TrufNetworkBridgeTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// TrufNetworkBridgeRaw is an auto generated low-level Go binding around an Ethereum contract.
type TrufNetworkBridgeRaw struct {
	Contract *TrufNetworkBridge // Generic contract binding to access the raw methods on
}

// TrufNetworkBridgeCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type TrufNetworkBridgeCallerRaw struct {
	Contract *TrufNetworkBridgeCaller // Generic read-only contract binding to access the raw methods on
}

// TrufNetworkBridgeTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type TrufNetworkBridgeTransactorRaw struct {
	Contract *TrufNetworkBridgeTransactor // Generic write-only contract binding to access the raw methods on
}

// NewTrufNetworkBridge creates a new instance of TrufNetworkBridge, bound to a specific deployed contract.
func NewTrufNetworkBridge(address common.Address, backend bind.ContractBackend) (*TrufNetworkBridge, error) {
	contract, err := bindTrufNetworkBridge(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridge{TrufNetworkBridgeCaller: TrufNetworkBridgeCaller{contract: contract}, TrufNetworkBridgeTransactor: TrufNetworkBridgeTransactor{contract: contract}, TrufNetworkBridgeFilterer: TrufNetworkBridgeFilterer{contract: contract}}, nil
}

// NewTrufNetworkBridgeCaller creates a new read-only instance of TrufNetworkBridge, bound to a specific deployed contract.
func NewTrufNetworkBridgeCaller(address common.Address, caller bind.ContractCaller) (*TrufNetworkBridgeCaller, error) {
	contract, err := bindTrufNetworkBridge(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeCaller{contract: contract}, nil
}

// NewTrufNetworkBridgeTransactor creates a new write-only instance of TrufNetworkBridge, bound to a specific deployed contract.
func NewTrufNetworkBridgeTransactor(address common.Address, transactor bind.ContractTransactor) (*TrufNetworkBridgeTransactor, error) {
	contract, err := bindTrufNetworkBridge(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeTransactor{contract: contract}, nil
}

// NewTrufNetworkBridgeFilterer creates a new log filterer instance of TrufNetworkBridge, bound to a specific deployed contract.
func NewTrufNetworkBridgeFilterer(address common.Address, filterer bind.ContractFilterer) (*TrufNetworkBridgeFilterer, error) {
	contract, err := bindTrufNetworkBridge(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeFilterer{contract: contract}, nil
}

// bindTrufNetworkBridge binds a generic wrapper to an already deployed contract.
func bindTrufNetworkBridge(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := TrufNetworkBridgeMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TrufNetworkBridge *TrufNetworkBridgeRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TrufNetworkBridge.Contract.TrufNetworkBridgeCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TrufNetworkBridge *TrufNetworkBridgeRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.TrufNetworkBridgeTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TrufNetworkBridge *TrufNetworkBridgeRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.TrufNetworkBridgeTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_TrufNetworkBridge *TrufNetworkBridgeCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _TrufNetworkBridge.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.contract.Transact(opts, method, params...)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_TrufNetworkBridge *TrufNetworkBridgeCaller) UPGRADEINTERFACEVERSION(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _TrufNetworkBridge.contract.Call(opts, &out, "UPGRADE_INTERFACE_VERSION")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_TrufNetworkBridge *TrufNetworkBridgeSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _TrufNetworkBridge.Contract.UPGRADEINTERFACEVERSION(&_TrufNetworkBridge.CallOpts)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_TrufNetworkBridge *TrufNetworkBridgeCallerSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _TrufNetworkBridge.Contract.UPGRADEINTERFACEVERSION(&_TrufNetworkBridge.CallOpts)
}

// GetBridgedToken is a free data retrieval call binding the contract method 0xcaeab7a3.
//
// Solidity: function getBridgedToken() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeCaller) GetBridgedToken(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _TrufNetworkBridge.contract.Call(opts, &out, "getBridgedToken")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// GetBridgedToken is a free data retrieval call binding the contract method 0xcaeab7a3.
//
// Solidity: function getBridgedToken() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeSession) GetBridgedToken() (common.Address, error) {
	return _TrufNetworkBridge.Contract.GetBridgedToken(&_TrufNetworkBridge.CallOpts)
}

// GetBridgedToken is a free data retrieval call binding the contract method 0xcaeab7a3.
//
// Solidity: function getBridgedToken() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeCallerSession) GetBridgedToken() (common.Address, error) {
	return _TrufNetworkBridge.Contract.GetBridgedToken(&_TrufNetworkBridge.CallOpts)
}

// GetRequiredSigners is a free data retrieval call binding the contract method 0xe0f1edc8.
//
// Solidity: function getRequiredSigners() view returns(uint256)
func (_TrufNetworkBridge *TrufNetworkBridgeCaller) GetRequiredSigners(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _TrufNetworkBridge.contract.Call(opts, &out, "getRequiredSigners")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetRequiredSigners is a free data retrieval call binding the contract method 0xe0f1edc8.
//
// Solidity: function getRequiredSigners() view returns(uint256)
func (_TrufNetworkBridge *TrufNetworkBridgeSession) GetRequiredSigners() (*big.Int, error) {
	return _TrufNetworkBridge.Contract.GetRequiredSigners(&_TrufNetworkBridge.CallOpts)
}

// GetRequiredSigners is a free data retrieval call binding the contract method 0xe0f1edc8.
//
// Solidity: function getRequiredSigners() view returns(uint256)
func (_TrufNetworkBridge *TrufNetworkBridgeCallerSession) GetRequiredSigners() (*big.Int, error) {
	return _TrufNetworkBridge.Contract.GetRequiredSigners(&_TrufNetworkBridge.CallOpts)
}

// GetSignerStatus is a free data retrieval call binding the contract method 0xe695402a.
//
// Solidity: function getSignerStatus(address signer) view returns(bool)
func (_TrufNetworkBridge *TrufNetworkBridgeCaller) GetSignerStatus(opts *bind.CallOpts, signer common.Address) (bool, error) {
	var out []interface{}
	err := _TrufNetworkBridge.contract.Call(opts, &out, "getSignerStatus", signer)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// GetSignerStatus is a free data retrieval call binding the contract method 0xe695402a.
//
// Solidity: function getSignerStatus(address signer) view returns(bool)
func (_TrufNetworkBridge *TrufNetworkBridgeSession) GetSignerStatus(signer common.Address) (bool, error) {
	return _TrufNetworkBridge.Contract.GetSignerStatus(&_TrufNetworkBridge.CallOpts, signer)
}

// GetSignerStatus is a free data retrieval call binding the contract method 0xe695402a.
//
// Solidity: function getSignerStatus(address signer) view returns(bool)
func (_TrufNetworkBridge *TrufNetworkBridgeCallerSession) GetSignerStatus(signer common.Address) (bool, error) {
	return _TrufNetworkBridge.Contract.GetSignerStatus(&_TrufNetworkBridge.CallOpts, signer)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _TrufNetworkBridge.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeSession) Owner() (common.Address, error) {
	return _TrufNetworkBridge.Contract.Owner(&_TrufNetworkBridge.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeCallerSession) Owner() (common.Address, error) {
	return _TrufNetworkBridge.Contract.Owner(&_TrufNetworkBridge.CallOpts)
}

// PendingOwner is a free data retrieval call binding the contract method 0xe30c3978.
//
// Solidity: function pendingOwner() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeCaller) PendingOwner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _TrufNetworkBridge.contract.Call(opts, &out, "pendingOwner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// PendingOwner is a free data retrieval call binding the contract method 0xe30c3978.
//
// Solidity: function pendingOwner() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeSession) PendingOwner() (common.Address, error) {
	return _TrufNetworkBridge.Contract.PendingOwner(&_TrufNetworkBridge.CallOpts)
}

// PendingOwner is a free data retrieval call binding the contract method 0xe30c3978.
//
// Solidity: function pendingOwner() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeCallerSession) PendingOwner() (common.Address, error) {
	return _TrufNetworkBridge.Contract.PendingOwner(&_TrufNetworkBridge.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_TrufNetworkBridge *TrufNetworkBridgeCaller) ProxiableUUID(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _TrufNetworkBridge.contract.Call(opts, &out, "proxiableUUID")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_TrufNetworkBridge *TrufNetworkBridgeSession) ProxiableUUID() ([32]byte, error) {
	return _TrufNetworkBridge.Contract.ProxiableUUID(&_TrufNetworkBridge.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_TrufNetworkBridge *TrufNetworkBridgeCallerSession) ProxiableUUID() ([32]byte, error) {
	return _TrufNetworkBridge.Contract.ProxiableUUID(&_TrufNetworkBridge.CallOpts)
}

// RewardToken is a free data retrieval call binding the contract method 0xf7c618c1.
//
// Solidity: function rewardToken() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeCaller) RewardToken(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _TrufNetworkBridge.contract.Call(opts, &out, "rewardToken")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// RewardToken is a free data retrieval call binding the contract method 0xf7c618c1.
//
// Solidity: function rewardToken() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeSession) RewardToken() (common.Address, error) {
	return _TrufNetworkBridge.Contract.RewardToken(&_TrufNetworkBridge.CallOpts)
}

// RewardToken is a free data retrieval call binding the contract method 0xf7c618c1.
//
// Solidity: function rewardToken() view returns(address)
func (_TrufNetworkBridge *TrufNetworkBridgeCallerSession) RewardToken() (common.Address, error) {
	return _TrufNetworkBridge.Contract.RewardToken(&_TrufNetworkBridge.CallOpts)
}

// AcceptOwnership is a paid mutator transaction binding the contract method 0x79ba5097.
//
// Solidity: function acceptOwnership() returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) AcceptOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "acceptOwnership")
}

// AcceptOwnership is a paid mutator transaction binding the contract method 0x79ba5097.
//
// Solidity: function acceptOwnership() returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) AcceptOwnership() (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.AcceptOwnership(&_TrufNetworkBridge.TransactOpts)
}

// AcceptOwnership is a paid mutator transaction binding the contract method 0x79ba5097.
//
// Solidity: function acceptOwnership() returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) AcceptOwnership() (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.AcceptOwnership(&_TrufNetworkBridge.TransactOpts)
}

// Deposit is a paid mutator transaction binding the contract method 0x6e553f65.
//
// Solidity: function deposit(uint256 amount, address recipient) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) Deposit(opts *bind.TransactOpts, amount *big.Int, recipient common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "deposit", amount, recipient)
}

// Deposit is a paid mutator transaction binding the contract method 0x6e553f65.
//
// Solidity: function deposit(uint256 amount, address recipient) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) Deposit(amount *big.Int, recipient common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.Deposit(&_TrufNetworkBridge.TransactOpts, amount, recipient)
}

// Deposit is a paid mutator transaction binding the contract method 0x6e553f65.
//
// Solidity: function deposit(uint256 amount, address recipient) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) Deposit(amount *big.Int, recipient common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.Deposit(&_TrufNetworkBridge.TransactOpts, amount, recipient)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address _owner, address _bridgedToken) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) Initialize(opts *bind.TransactOpts, _owner common.Address, _bridgedToken common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "initialize", _owner, _bridgedToken)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address _owner, address _bridgedToken) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) Initialize(_owner common.Address, _bridgedToken common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.Initialize(&_TrufNetworkBridge.TransactOpts, _owner, _bridgedToken)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address _owner, address _bridgedToken) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) Initialize(_owner common.Address, _bridgedToken common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.Initialize(&_TrufNetworkBridge.TransactOpts, _owner, _bridgedToken)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) RenounceOwnership() (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.RenounceOwnership(&_TrufNetworkBridge.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.RenounceOwnership(&_TrufNetworkBridge.TransactOpts)
}

// SetRequiredSigners is a paid mutator transaction binding the contract method 0xa502afe0.
//
// Solidity: function setRequiredSigners(uint256 requiredSigners) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) SetRequiredSigners(opts *bind.TransactOpts, requiredSigners *big.Int) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "setRequiredSigners", requiredSigners)
}

// SetRequiredSigners is a paid mutator transaction binding the contract method 0xa502afe0.
//
// Solidity: function setRequiredSigners(uint256 requiredSigners) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) SetRequiredSigners(requiredSigners *big.Int) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.SetRequiredSigners(&_TrufNetworkBridge.TransactOpts, requiredSigners)
}

// SetRequiredSigners is a paid mutator transaction binding the contract method 0xa502afe0.
//
// Solidity: function setRequiredSigners(uint256 requiredSigners) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) SetRequiredSigners(requiredSigners *big.Int) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.SetRequiredSigners(&_TrufNetworkBridge.TransactOpts, requiredSigners)
}

// SetSigner is a paid mutator transaction binding the contract method 0x31cb6105.
//
// Solidity: function setSigner(address signer, bool isSigner) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) SetSigner(opts *bind.TransactOpts, signer common.Address, isSigner bool) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "setSigner", signer, isSigner)
}

// SetSigner is a paid mutator transaction binding the contract method 0x31cb6105.
//
// Solidity: function setSigner(address signer, bool isSigner) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) SetSigner(signer common.Address, isSigner bool) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.SetSigner(&_TrufNetworkBridge.TransactOpts, signer, isSigner)
}

// SetSigner is a paid mutator transaction binding the contract method 0x31cb6105.
//
// Solidity: function setSigner(address signer, bool isSigner) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) SetSigner(signer common.Address, isSigner bool) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.SetSigner(&_TrufNetworkBridge.TransactOpts, signer, isSigner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.TransferOwnership(&_TrufNetworkBridge.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.TransferOwnership(&_TrufNetworkBridge.TransactOpts, newOwner)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) UpgradeToAndCall(opts *bind.TransactOpts, newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "upgradeToAndCall", newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.UpgradeToAndCall(&_TrufNetworkBridge.TransactOpts, newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.UpgradeToAndCall(&_TrufNetworkBridge.TransactOpts, newImplementation, data)
}

// Withdraw is a paid mutator transaction binding the contract method 0x6edf330d.
//
// Solidity: function withdraw(address recipient, uint256 amount, bytes32 kwilBlockHash, bytes32 root, bytes32[] proof, (uint8,bytes32,bytes32)[] signatures) payable returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactor) Withdraw(opts *bind.TransactOpts, recipient common.Address, amount *big.Int, kwilBlockHash [32]byte, root [32]byte, proof [][32]byte, signatures []ITrufNetworkBridgeSignature) (*types.Transaction, error) {
	return _TrufNetworkBridge.contract.Transact(opts, "withdraw", recipient, amount, kwilBlockHash, root, proof, signatures)
}

// Withdraw is a paid mutator transaction binding the contract method 0x6edf330d.
//
// Solidity: function withdraw(address recipient, uint256 amount, bytes32 kwilBlockHash, bytes32 root, bytes32[] proof, (uint8,bytes32,bytes32)[] signatures) payable returns()
func (_TrufNetworkBridge *TrufNetworkBridgeSession) Withdraw(recipient common.Address, amount *big.Int, kwilBlockHash [32]byte, root [32]byte, proof [][32]byte, signatures []ITrufNetworkBridgeSignature) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.Withdraw(&_TrufNetworkBridge.TransactOpts, recipient, amount, kwilBlockHash, root, proof, signatures)
}

// Withdraw is a paid mutator transaction binding the contract method 0x6edf330d.
//
// Solidity: function withdraw(address recipient, uint256 amount, bytes32 kwilBlockHash, bytes32 root, bytes32[] proof, (uint8,bytes32,bytes32)[] signatures) payable returns()
func (_TrufNetworkBridge *TrufNetworkBridgeTransactorSession) Withdraw(recipient common.Address, amount *big.Int, kwilBlockHash [32]byte, root [32]byte, proof [][32]byte, signatures []ITrufNetworkBridgeSignature) (*types.Transaction, error) {
	return _TrufNetworkBridge.Contract.Withdraw(&_TrufNetworkBridge.TransactOpts, recipient, amount, kwilBlockHash, root, proof, signatures)
}

// TrufNetworkBridgeDepositIterator is returned from FilterDeposit and is used to iterate over the raw logs and unpacked data for Deposit events raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeDepositIterator struct {
	Event *TrufNetworkBridgeDeposit // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TrufNetworkBridgeDepositIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TrufNetworkBridgeDeposit)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TrufNetworkBridgeDeposit)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TrufNetworkBridgeDepositIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TrufNetworkBridgeDepositIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TrufNetworkBridgeDeposit represents a Deposit event raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeDeposit struct {
	Recipient common.Address
	Amount    *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterDeposit is a free log retrieval operation binding the contract event 0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c.
//
// Solidity: event Deposit(address indexed recipient, uint256 amount)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) FilterDeposit(opts *bind.FilterOpts, recipient []common.Address) (*TrufNetworkBridgeDepositIterator, error) {

	var recipientRule []interface{}
	for _, recipientItem := range recipient {
		recipientRule = append(recipientRule, recipientItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.FilterLogs(opts, "Deposit", recipientRule)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeDepositIterator{contract: _TrufNetworkBridge.contract, event: "Deposit", logs: logs, sub: sub}, nil
}

// WatchDeposit is a free log subscription operation binding the contract event 0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c.
//
// Solidity: event Deposit(address indexed recipient, uint256 amount)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) WatchDeposit(opts *bind.WatchOpts, sink chan<- *TrufNetworkBridgeDeposit, recipient []common.Address) (event.Subscription, error) {

	var recipientRule []interface{}
	for _, recipientItem := range recipient {
		recipientRule = append(recipientRule, recipientItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.WatchLogs(opts, "Deposit", recipientRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TrufNetworkBridgeDeposit)
				if err := _TrufNetworkBridge.contract.UnpackLog(event, "Deposit", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseDeposit is a log parse operation binding the contract event 0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c.
//
// Solidity: event Deposit(address indexed recipient, uint256 amount)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) ParseDeposit(log types.Log) (*TrufNetworkBridgeDeposit, error) {
	event := new(TrufNetworkBridgeDeposit)
	if err := _TrufNetworkBridge.contract.UnpackLog(event, "Deposit", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TrufNetworkBridgeInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeInitializedIterator struct {
	Event *TrufNetworkBridgeInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TrufNetworkBridgeInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TrufNetworkBridgeInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TrufNetworkBridgeInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TrufNetworkBridgeInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TrufNetworkBridgeInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TrufNetworkBridgeInitialized represents a Initialized event raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeInitialized struct {
	Version uint64
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) FilterInitialized(opts *bind.FilterOpts) (*TrufNetworkBridgeInitializedIterator, error) {

	logs, sub, err := _TrufNetworkBridge.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeInitializedIterator{contract: _TrufNetworkBridge.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *TrufNetworkBridgeInitialized) (event.Subscription, error) {

	logs, sub, err := _TrufNetworkBridge.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TrufNetworkBridgeInitialized)
				if err := _TrufNetworkBridge.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) ParseInitialized(log types.Log) (*TrufNetworkBridgeInitialized, error) {
	event := new(TrufNetworkBridgeInitialized)
	if err := _TrufNetworkBridge.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TrufNetworkBridgeOwnershipTransferStartedIterator is returned from FilterOwnershipTransferStarted and is used to iterate over the raw logs and unpacked data for OwnershipTransferStarted events raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeOwnershipTransferStartedIterator struct {
	Event *TrufNetworkBridgeOwnershipTransferStarted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TrufNetworkBridgeOwnershipTransferStartedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TrufNetworkBridgeOwnershipTransferStarted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TrufNetworkBridgeOwnershipTransferStarted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TrufNetworkBridgeOwnershipTransferStartedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TrufNetworkBridgeOwnershipTransferStartedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TrufNetworkBridgeOwnershipTransferStarted represents a OwnershipTransferStarted event raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeOwnershipTransferStarted struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferStarted is a free log retrieval operation binding the contract event 0x38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e22700.
//
// Solidity: event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) FilterOwnershipTransferStarted(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*TrufNetworkBridgeOwnershipTransferStartedIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.FilterLogs(opts, "OwnershipTransferStarted", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeOwnershipTransferStartedIterator{contract: _TrufNetworkBridge.contract, event: "OwnershipTransferStarted", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferStarted is a free log subscription operation binding the contract event 0x38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e22700.
//
// Solidity: event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) WatchOwnershipTransferStarted(opts *bind.WatchOpts, sink chan<- *TrufNetworkBridgeOwnershipTransferStarted, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.WatchLogs(opts, "OwnershipTransferStarted", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TrufNetworkBridgeOwnershipTransferStarted)
				if err := _TrufNetworkBridge.contract.UnpackLog(event, "OwnershipTransferStarted", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferStarted is a log parse operation binding the contract event 0x38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e22700.
//
// Solidity: event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) ParseOwnershipTransferStarted(log types.Log) (*TrufNetworkBridgeOwnershipTransferStarted, error) {
	event := new(TrufNetworkBridgeOwnershipTransferStarted)
	if err := _TrufNetworkBridge.contract.UnpackLog(event, "OwnershipTransferStarted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TrufNetworkBridgeOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeOwnershipTransferredIterator struct {
	Event *TrufNetworkBridgeOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TrufNetworkBridgeOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TrufNetworkBridgeOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TrufNetworkBridgeOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TrufNetworkBridgeOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TrufNetworkBridgeOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TrufNetworkBridgeOwnershipTransferred represents a OwnershipTransferred event raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*TrufNetworkBridgeOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeOwnershipTransferredIterator{contract: _TrufNetworkBridge.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *TrufNetworkBridgeOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TrufNetworkBridgeOwnershipTransferred)
				if err := _TrufNetworkBridge.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) ParseOwnershipTransferred(log types.Log) (*TrufNetworkBridgeOwnershipTransferred, error) {
	event := new(TrufNetworkBridgeOwnershipTransferred)
	if err := _TrufNetworkBridge.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TrufNetworkBridgeRequiredSignersSetIterator is returned from FilterRequiredSignersSet and is used to iterate over the raw logs and unpacked data for RequiredSignersSet events raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeRequiredSignersSetIterator struct {
	Event *TrufNetworkBridgeRequiredSignersSet // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TrufNetworkBridgeRequiredSignersSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TrufNetworkBridgeRequiredSignersSet)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TrufNetworkBridgeRequiredSignersSet)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TrufNetworkBridgeRequiredSignersSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TrufNetworkBridgeRequiredSignersSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TrufNetworkBridgeRequiredSignersSet represents a RequiredSignersSet event raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeRequiredSignersSet struct {
	RequiredSigners *big.Int
	Raw             types.Log // Blockchain specific contextual infos
}

// FilterRequiredSignersSet is a free log retrieval operation binding the contract event 0x0d3fe2a10cf3e4a5a122983b2d1b8dce98d30526f5c0e3ad91b1973862fc2efa.
//
// Solidity: event RequiredSignersSet(uint256 requiredSigners)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) FilterRequiredSignersSet(opts *bind.FilterOpts) (*TrufNetworkBridgeRequiredSignersSetIterator, error) {

	logs, sub, err := _TrufNetworkBridge.contract.FilterLogs(opts, "RequiredSignersSet")
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeRequiredSignersSetIterator{contract: _TrufNetworkBridge.contract, event: "RequiredSignersSet", logs: logs, sub: sub}, nil
}

// WatchRequiredSignersSet is a free log subscription operation binding the contract event 0x0d3fe2a10cf3e4a5a122983b2d1b8dce98d30526f5c0e3ad91b1973862fc2efa.
//
// Solidity: event RequiredSignersSet(uint256 requiredSigners)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) WatchRequiredSignersSet(opts *bind.WatchOpts, sink chan<- *TrufNetworkBridgeRequiredSignersSet) (event.Subscription, error) {

	logs, sub, err := _TrufNetworkBridge.contract.WatchLogs(opts, "RequiredSignersSet")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TrufNetworkBridgeRequiredSignersSet)
				if err := _TrufNetworkBridge.contract.UnpackLog(event, "RequiredSignersSet", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRequiredSignersSet is a log parse operation binding the contract event 0x0d3fe2a10cf3e4a5a122983b2d1b8dce98d30526f5c0e3ad91b1973862fc2efa.
//
// Solidity: event RequiredSignersSet(uint256 requiredSigners)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) ParseRequiredSignersSet(log types.Log) (*TrufNetworkBridgeRequiredSignersSet, error) {
	event := new(TrufNetworkBridgeRequiredSignersSet)
	if err := _TrufNetworkBridge.contract.UnpackLog(event, "RequiredSignersSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TrufNetworkBridgeSignerSetIterator is returned from FilterSignerSet and is used to iterate over the raw logs and unpacked data for SignerSet events raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeSignerSetIterator struct {
	Event *TrufNetworkBridgeSignerSet // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TrufNetworkBridgeSignerSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TrufNetworkBridgeSignerSet)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TrufNetworkBridgeSignerSet)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TrufNetworkBridgeSignerSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TrufNetworkBridgeSignerSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TrufNetworkBridgeSignerSet represents a SignerSet event raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeSignerSet struct {
	Signer   common.Address
	IsSigner bool
	Raw      types.Log // Blockchain specific contextual infos
}

// FilterSignerSet is a free log retrieval operation binding the contract event 0xfc4acb499491cd850a8a21ab98c7f128850c0f0e5f1a875a62b7fa055c2ecf19.
//
// Solidity: event SignerSet(address indexed signer, bool isSigner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) FilterSignerSet(opts *bind.FilterOpts, signer []common.Address) (*TrufNetworkBridgeSignerSetIterator, error) {

	var signerRule []interface{}
	for _, signerItem := range signer {
		signerRule = append(signerRule, signerItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.FilterLogs(opts, "SignerSet", signerRule)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeSignerSetIterator{contract: _TrufNetworkBridge.contract, event: "SignerSet", logs: logs, sub: sub}, nil
}

// WatchSignerSet is a free log subscription operation binding the contract event 0xfc4acb499491cd850a8a21ab98c7f128850c0f0e5f1a875a62b7fa055c2ecf19.
//
// Solidity: event SignerSet(address indexed signer, bool isSigner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) WatchSignerSet(opts *bind.WatchOpts, sink chan<- *TrufNetworkBridgeSignerSet, signer []common.Address) (event.Subscription, error) {

	var signerRule []interface{}
	for _, signerItem := range signer {
		signerRule = append(signerRule, signerItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.WatchLogs(opts, "SignerSet", signerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TrufNetworkBridgeSignerSet)
				if err := _TrufNetworkBridge.contract.UnpackLog(event, "SignerSet", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseSignerSet is a log parse operation binding the contract event 0xfc4acb499491cd850a8a21ab98c7f128850c0f0e5f1a875a62b7fa055c2ecf19.
//
// Solidity: event SignerSet(address indexed signer, bool isSigner)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) ParseSignerSet(log types.Log) (*TrufNetworkBridgeSignerSet, error) {
	event := new(TrufNetworkBridgeSignerSet)
	if err := _TrufNetworkBridge.contract.UnpackLog(event, "SignerSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TrufNetworkBridgeUpgradedIterator is returned from FilterUpgraded and is used to iterate over the raw logs and unpacked data for Upgraded events raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeUpgradedIterator struct {
	Event *TrufNetworkBridgeUpgraded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TrufNetworkBridgeUpgradedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TrufNetworkBridgeUpgraded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TrufNetworkBridgeUpgraded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TrufNetworkBridgeUpgradedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TrufNetworkBridgeUpgradedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TrufNetworkBridgeUpgraded represents a Upgraded event raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeUpgraded struct {
	Implementation common.Address
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterUpgraded is a free log retrieval operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) FilterUpgraded(opts *bind.FilterOpts, implementation []common.Address) (*TrufNetworkBridgeUpgradedIterator, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.FilterLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeUpgradedIterator{contract: _TrufNetworkBridge.contract, event: "Upgraded", logs: logs, sub: sub}, nil
}

// WatchUpgraded is a free log subscription operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) WatchUpgraded(opts *bind.WatchOpts, sink chan<- *TrufNetworkBridgeUpgraded, implementation []common.Address) (event.Subscription, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.WatchLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TrufNetworkBridgeUpgraded)
				if err := _TrufNetworkBridge.contract.UnpackLog(event, "Upgraded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUpgraded is a log parse operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) ParseUpgraded(log types.Log) (*TrufNetworkBridgeUpgraded, error) {
	event := new(TrufNetworkBridgeUpgraded)
	if err := _TrufNetworkBridge.contract.UnpackLog(event, "Upgraded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// TrufNetworkBridgeWithdrawIterator is returned from FilterWithdraw and is used to iterate over the raw logs and unpacked data for Withdraw events raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeWithdrawIterator struct {
	Event *TrufNetworkBridgeWithdraw // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *TrufNetworkBridgeWithdrawIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(TrufNetworkBridgeWithdraw)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(TrufNetworkBridgeWithdraw)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *TrufNetworkBridgeWithdrawIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *TrufNetworkBridgeWithdrawIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// TrufNetworkBridgeWithdraw represents a Withdraw event raised by the TrufNetworkBridge contract.
type TrufNetworkBridgeWithdraw struct {
	Recipient     common.Address
	Amount        *big.Int
	KwilBlockHash [32]byte
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterWithdraw is a free log retrieval operation binding the contract event 0x4d911754a3efbbc2e0463de4f6bff32ed24421d1c89c11dce59a4935f327afff.
//
// Solidity: event Withdraw(address indexed recipient, uint256 amount, bytes32 indexed kwilBlockHash)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) FilterWithdraw(opts *bind.FilterOpts, recipient []common.Address, kwilBlockHash [][32]byte) (*TrufNetworkBridgeWithdrawIterator, error) {

	var recipientRule []interface{}
	for _, recipientItem := range recipient {
		recipientRule = append(recipientRule, recipientItem)
	}

	var kwilBlockHashRule []interface{}
	for _, kwilBlockHashItem := range kwilBlockHash {
		kwilBlockHashRule = append(kwilBlockHashRule, kwilBlockHashItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.FilterLogs(opts, "Withdraw", recipientRule, kwilBlockHashRule)
	if err != nil {
		return nil, err
	}
	return &TrufNetworkBridgeWithdrawIterator{contract: _TrufNetworkBridge.contract, event: "Withdraw", logs: logs, sub: sub}, nil
}

// WatchWithdraw is a free log subscription operation binding the contract event 0x4d911754a3efbbc2e0463de4f6bff32ed24421d1c89c11dce59a4935f327afff.
//
// Solidity: event Withdraw(address indexed recipient, uint256 amount, bytes32 indexed kwilBlockHash)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) WatchWithdraw(opts *bind.WatchOpts, sink chan<- *TrufNetworkBridgeWithdraw, recipient []common.Address, kwilBlockHash [][32]byte) (event.Subscription, error) {

	var recipientRule []interface{}
	for _, recipientItem := range recipient {
		recipientRule = append(recipientRule, recipientItem)
	}

	var kwilBlockHashRule []interface{}
	for _, kwilBlockHashItem := range kwilBlockHash {
		kwilBlockHashRule = append(kwilBlockHashRule, kwilBlockHashItem)
	}

	logs, sub, err := _TrufNetworkBridge.contract.WatchLogs(opts, "Withdraw", recipientRule, kwilBlockHashRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(TrufNetworkBridgeWithdraw)
				if err := _TrufNetworkBridge.contract.UnpackLog(event, "Withdraw", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseWithdraw is a log parse operation binding the contract event 0x4d911754a3efbbc2e0463de4f6bff32ed24421d1c89c11dce59a4935f327afff.
//
// Solidity: event Withdraw(address indexed recipient, uint256 amount, bytes32 indexed kwilBlockHash)
func (_TrufNetworkBridge *TrufNetworkBridgeFilterer) ParseWithdraw(log types.Log) (*TrufNetworkBridgeWithdraw, error) {
	event := new(TrufNetworkBridgeWithdraw)
	if err := _TrufNetworkBridge.contract.UnpackLog(event, "Withdraw", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

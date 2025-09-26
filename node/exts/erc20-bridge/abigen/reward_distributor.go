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

// RewardDistributorMetaData contains all meta data concerning the RewardDistributor contract.
var RewardDistributorMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"ReentrancyGuardReentrantCall\",\"type\":\"error\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"oldFee\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"newFee\",\"type\":\"uint256\"}],\"name\":\"PosterFeeUpdated\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"claimer\",\"type\":\"address\"}],\"name\":\"RewardClaimed\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"indexed\":false,\"internalType\":\"address\",\"name\":\"poster\",\"type\":\"address\"}],\"name\":\"RewardPosted\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":false,\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"indexed\":false,\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"Deposit\",\"type\":\"event\"},{\"stateMutability\":\"payable\",\"type\":\"fallback\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"kwilBlockHash\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"rewardRoot\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32[]\",\"name\":\"proofs\",\"type\":\"bytes32[]\"}],\"name\":\"claimReward\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"isRewardClaimed\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"postReward\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"recipient\",\"type\":\"address\"}],\"name\":\"deposit\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"postedRewards\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"posterFee\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"rewardPoster\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"rewardToken\",\"outputs\":[{\"internalType\":\"contractIERC20\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"safe\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_safe\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_posterFee\",\"type\":\"uint256\"},{\"internalType\":\"address\",\"name\":\"_rewardToken\",\"type\":\"address\"}],\"name\":\"setup\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"unpostedRewards\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"newFee\",\"type\":\"uint256\"}],\"name\":\"updatePosterFee\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"stateMutability\":\"payable\",\"type\":\"receive\"}]",
}

// RewardDistributorABI is the input ABI used to generate the binding from.
// Deprecated: Use RewardDistributorMetaData.ABI instead.
var RewardDistributorABI = RewardDistributorMetaData.ABI

// RewardDistributor is an auto generated Go binding around an Ethereum contract.
type RewardDistributor struct {
	RewardDistributorCaller     // Read-only binding to the contract
	RewardDistributorTransactor // Write-only binding to the contract
	RewardDistributorFilterer   // Log filterer for contract events
}

// RewardDistributorCaller is an auto generated read-only Go binding around an Ethereum contract.
type RewardDistributorCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RewardDistributorTransactor is an auto generated write-only Go binding around an Ethereum contract.
type RewardDistributorTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RewardDistributorFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type RewardDistributorFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// RewardDistributorSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type RewardDistributorSession struct {
	Contract     *RewardDistributor // Generic contract binding to set the session for
	CallOpts     bind.CallOpts      // Call options to use throughout this session
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// RewardDistributorCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type RewardDistributorCallerSession struct {
	Contract *RewardDistributorCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts            // Call options to use throughout this session
}

// RewardDistributorTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type RewardDistributorTransactorSession struct {
	Contract     *RewardDistributorTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts            // Transaction auth options to use throughout this session
}

// RewardDistributorRaw is an auto generated low-level Go binding around an Ethereum contract.
type RewardDistributorRaw struct {
	Contract *RewardDistributor // Generic contract binding to access the raw methods on
}

// RewardDistributorCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type RewardDistributorCallerRaw struct {
	Contract *RewardDistributorCaller // Generic read-only contract binding to access the raw methods on
}

// RewardDistributorTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type RewardDistributorTransactorRaw struct {
	Contract *RewardDistributorTransactor // Generic write-only contract binding to access the raw methods on
}

// NewRewardDistributor creates a new instance of RewardDistributor, bound to a specific deployed contract.
func NewRewardDistributor(address common.Address, backend bind.ContractBackend) (*RewardDistributor, error) {
	contract, err := bindRewardDistributor(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &RewardDistributor{RewardDistributorCaller: RewardDistributorCaller{contract: contract}, RewardDistributorTransactor: RewardDistributorTransactor{contract: contract}, RewardDistributorFilterer: RewardDistributorFilterer{contract: contract}}, nil
}

// NewRewardDistributorCaller creates a new read-only instance of RewardDistributor, bound to a specific deployed contract.
func NewRewardDistributorCaller(address common.Address, caller bind.ContractCaller) (*RewardDistributorCaller, error) {
	contract, err := bindRewardDistributor(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &RewardDistributorCaller{contract: contract}, nil
}

// NewRewardDistributorTransactor creates a new write-only instance of RewardDistributor, bound to a specific deployed contract.
func NewRewardDistributorTransactor(address common.Address, transactor bind.ContractTransactor) (*RewardDistributorTransactor, error) {
	contract, err := bindRewardDistributor(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &RewardDistributorTransactor{contract: contract}, nil
}

// NewRewardDistributorFilterer creates a new log filterer instance of RewardDistributor, bound to a specific deployed contract.
func NewRewardDistributorFilterer(address common.Address, filterer bind.ContractFilterer) (*RewardDistributorFilterer, error) {
	contract, err := bindRewardDistributor(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &RewardDistributorFilterer{contract: contract}, nil
}

// bindRewardDistributor binds a generic wrapper to an already deployed contract.
func bindRewardDistributor(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := RewardDistributorMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RewardDistributor *RewardDistributorRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _RewardDistributor.Contract.RewardDistributorCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RewardDistributor *RewardDistributorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RewardDistributor.Contract.RewardDistributorTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RewardDistributor *RewardDistributorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RewardDistributor.Contract.RewardDistributorTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_RewardDistributor *RewardDistributorCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _RewardDistributor.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_RewardDistributor *RewardDistributorTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RewardDistributor.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_RewardDistributor *RewardDistributorTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _RewardDistributor.Contract.contract.Transact(opts, method, params...)
}

// IsRewardClaimed is a free data retrieval call binding the contract method 0x27dda893.
//
// Solidity: function isRewardClaimed(bytes32 , bytes32 ) view returns(bool)
func (_RewardDistributor *RewardDistributorCaller) IsRewardClaimed(opts *bind.CallOpts, arg0 [32]byte, arg1 [32]byte) (bool, error) {
	var out []interface{}
	err := _RewardDistributor.contract.Call(opts, &out, "isRewardClaimed", arg0, arg1)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsRewardClaimed is a free data retrieval call binding the contract method 0x27dda893.
//
// Solidity: function isRewardClaimed(bytes32 , bytes32 ) view returns(bool)
func (_RewardDistributor *RewardDistributorSession) IsRewardClaimed(arg0 [32]byte, arg1 [32]byte) (bool, error) {
	return _RewardDistributor.Contract.IsRewardClaimed(&_RewardDistributor.CallOpts, arg0, arg1)
}

// IsRewardClaimed is a free data retrieval call binding the contract method 0x27dda893.
//
// Solidity: function isRewardClaimed(bytes32 , bytes32 ) view returns(bool)
func (_RewardDistributor *RewardDistributorCallerSession) IsRewardClaimed(arg0 [32]byte, arg1 [32]byte) (bool, error) {
	return _RewardDistributor.Contract.IsRewardClaimed(&_RewardDistributor.CallOpts, arg0, arg1)
}

// PostedRewards is a free data retrieval call binding the contract method 0x122d52de.
//
// Solidity: function postedRewards() view returns(uint256)
func (_RewardDistributor *RewardDistributorCaller) PostedRewards(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _RewardDistributor.contract.Call(opts, &out, "postedRewards")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// PostedRewards is a free data retrieval call binding the contract method 0x122d52de.
//
// Solidity: function postedRewards() view returns(uint256)
func (_RewardDistributor *RewardDistributorSession) PostedRewards() (*big.Int, error) {
	return _RewardDistributor.Contract.PostedRewards(&_RewardDistributor.CallOpts)
}

// PostedRewards is a free data retrieval call binding the contract method 0x122d52de.
//
// Solidity: function postedRewards() view returns(uint256)
func (_RewardDistributor *RewardDistributorCallerSession) PostedRewards() (*big.Int, error) {
	return _RewardDistributor.Contract.PostedRewards(&_RewardDistributor.CallOpts)
}

// PosterFee is a free data retrieval call binding the contract method 0x408422bc.
//
// Solidity: function posterFee() view returns(uint256)
func (_RewardDistributor *RewardDistributorCaller) PosterFee(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _RewardDistributor.contract.Call(opts, &out, "posterFee")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// PosterFee is a free data retrieval call binding the contract method 0x408422bc.
//
// Solidity: function posterFee() view returns(uint256)
func (_RewardDistributor *RewardDistributorSession) PosterFee() (*big.Int, error) {
	return _RewardDistributor.Contract.PosterFee(&_RewardDistributor.CallOpts)
}

// PosterFee is a free data retrieval call binding the contract method 0x408422bc.
//
// Solidity: function posterFee() view returns(uint256)
func (_RewardDistributor *RewardDistributorCallerSession) PosterFee() (*big.Int, error) {
	return _RewardDistributor.Contract.PosterFee(&_RewardDistributor.CallOpts)
}

// RewardPoster is a free data retrieval call binding the contract method 0x75cbd82d.
//
// Solidity: function rewardPoster(bytes32 ) view returns(address)
func (_RewardDistributor *RewardDistributorCaller) RewardPoster(opts *bind.CallOpts, arg0 [32]byte) (common.Address, error) {
	var out []interface{}
	err := _RewardDistributor.contract.Call(opts, &out, "rewardPoster", arg0)

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// RewardPoster is a free data retrieval call binding the contract method 0x75cbd82d.
//
// Solidity: function rewardPoster(bytes32 ) view returns(address)
func (_RewardDistributor *RewardDistributorSession) RewardPoster(arg0 [32]byte) (common.Address, error) {
	return _RewardDistributor.Contract.RewardPoster(&_RewardDistributor.CallOpts, arg0)
}

// RewardPoster is a free data retrieval call binding the contract method 0x75cbd82d.
//
// Solidity: function rewardPoster(bytes32 ) view returns(address)
func (_RewardDistributor *RewardDistributorCallerSession) RewardPoster(arg0 [32]byte) (common.Address, error) {
	return _RewardDistributor.Contract.RewardPoster(&_RewardDistributor.CallOpts, arg0)
}

// RewardToken is a free data retrieval call binding the contract method 0xf7c618c1.
//
// Solidity: function rewardToken() view returns(address)
func (_RewardDistributor *RewardDistributorCaller) RewardToken(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _RewardDistributor.contract.Call(opts, &out, "rewardToken")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// RewardToken is a free data retrieval call binding the contract method 0xf7c618c1.
//
// Solidity: function rewardToken() view returns(address)
func (_RewardDistributor *RewardDistributorSession) RewardToken() (common.Address, error) {
	return _RewardDistributor.Contract.RewardToken(&_RewardDistributor.CallOpts)
}

// RewardToken is a free data retrieval call binding the contract method 0xf7c618c1.
//
// Solidity: function rewardToken() view returns(address)
func (_RewardDistributor *RewardDistributorCallerSession) RewardToken() (common.Address, error) {
	return _RewardDistributor.Contract.RewardToken(&_RewardDistributor.CallOpts)
}

// Safe is a free data retrieval call binding the contract method 0x186f0354.
//
// Solidity: function safe() view returns(address)
func (_RewardDistributor *RewardDistributorCaller) Safe(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _RewardDistributor.contract.Call(opts, &out, "safe")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Safe is a free data retrieval call binding the contract method 0x186f0354.
//
// Solidity: function safe() view returns(address)
func (_RewardDistributor *RewardDistributorSession) Safe() (common.Address, error) {
	return _RewardDistributor.Contract.Safe(&_RewardDistributor.CallOpts)
}

// Safe is a free data retrieval call binding the contract method 0x186f0354.
//
// Solidity: function safe() view returns(address)
func (_RewardDistributor *RewardDistributorCallerSession) Safe() (common.Address, error) {
	return _RewardDistributor.Contract.Safe(&_RewardDistributor.CallOpts)
}

// UnpostedRewards is a free data retrieval call binding the contract method 0xd5cf76f5.
//
// Solidity: function unpostedRewards() view returns(uint256)
func (_RewardDistributor *RewardDistributorCaller) UnpostedRewards(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _RewardDistributor.contract.Call(opts, &out, "unpostedRewards")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// UnpostedRewards is a free data retrieval call binding the contract method 0xd5cf76f5.
//
// Solidity: function unpostedRewards() view returns(uint256)
func (_RewardDistributor *RewardDistributorSession) UnpostedRewards() (*big.Int, error) {
	return _RewardDistributor.Contract.UnpostedRewards(&_RewardDistributor.CallOpts)
}

// UnpostedRewards is a free data retrieval call binding the contract method 0xd5cf76f5.
//
// Solidity: function unpostedRewards() view returns(uint256)
func (_RewardDistributor *RewardDistributorCallerSession) UnpostedRewards() (*big.Int, error) {
	return _RewardDistributor.Contract.UnpostedRewards(&_RewardDistributor.CallOpts)
}

// ClaimReward is a paid mutator transaction binding the contract method 0x63e6a87c.
//
// Solidity: function claimReward(address recipient, uint256 amount, bytes32 kwilBlockHash, bytes32 rewardRoot, bytes32[] proofs) payable returns()
func (_RewardDistributor *RewardDistributorTransactor) ClaimReward(opts *bind.TransactOpts, recipient common.Address, amount *big.Int, kwilBlockHash [32]byte, rewardRoot [32]byte, proofs [][32]byte) (*types.Transaction, error) {
	return _RewardDistributor.contract.Transact(opts, "claimReward", recipient, amount, kwilBlockHash, rewardRoot, proofs)
}

// ClaimReward is a paid mutator transaction binding the contract method 0x63e6a87c.
//
// Solidity: function claimReward(address recipient, uint256 amount, bytes32 kwilBlockHash, bytes32 rewardRoot, bytes32[] proofs) payable returns()
func (_RewardDistributor *RewardDistributorSession) ClaimReward(recipient common.Address, amount *big.Int, kwilBlockHash [32]byte, rewardRoot [32]byte, proofs [][32]byte) (*types.Transaction, error) {
	return _RewardDistributor.Contract.ClaimReward(&_RewardDistributor.TransactOpts, recipient, amount, kwilBlockHash, rewardRoot, proofs)
}

// ClaimReward is a paid mutator transaction binding the contract method 0x63e6a87c.
//
// Solidity: function claimReward(address recipient, uint256 amount, bytes32 kwilBlockHash, bytes32 rewardRoot, bytes32[] proofs) payable returns()
func (_RewardDistributor *RewardDistributorTransactorSession) ClaimReward(recipient common.Address, amount *big.Int, kwilBlockHash [32]byte, rewardRoot [32]byte, proofs [][32]byte) (*types.Transaction, error) {
	return _RewardDistributor.Contract.ClaimReward(&_RewardDistributor.TransactOpts, recipient, amount, kwilBlockHash, rewardRoot, proofs)
}

// Deposit is a paid mutator transaction binding the contract method 0x6e553f65.
//
// Solidity: function deposit(uint256 amount, address recipient) returns()
func (_RewardDistributor *RewardDistributorTransactor) Deposit(opts *bind.TransactOpts, amount *big.Int, recipient common.Address) (*types.Transaction, error) {
	return _RewardDistributor.contract.Transact(opts, "deposit", amount, recipient)
}

// Deposit is a paid mutator transaction binding the contract method 0x6e553f65.
//
// Solidity: function deposit(uint256 amount, address recipient) returns()
func (_RewardDistributor *RewardDistributorSession) Deposit(amount *big.Int, recipient common.Address) (*types.Transaction, error) {
	return _RewardDistributor.Contract.Deposit(&_RewardDistributor.TransactOpts, amount, recipient)
}

// Deposit is a paid mutator transaction binding the contract method 0x6e553f65.
//
// Solidity: function deposit(uint256 amount, address recipient) returns()
func (_RewardDistributor *RewardDistributorTransactorSession) Deposit(amount *big.Int, recipient common.Address) (*types.Transaction, error) {
	return _RewardDistributor.Contract.Deposit(&_RewardDistributor.TransactOpts, amount, recipient)
}

// PostReward is a paid mutator transaction binding the contract method 0xeb630dd3.
//
// Solidity: function postReward(bytes32 root, uint256 amount) returns()
func (_RewardDistributor *RewardDistributorTransactor) PostReward(opts *bind.TransactOpts, root [32]byte, amount *big.Int) (*types.Transaction, error) {
	return _RewardDistributor.contract.Transact(opts, "postReward", root, amount)
}

// PostReward is a paid mutator transaction binding the contract method 0xeb630dd3.
//
// Solidity: function postReward(bytes32 root, uint256 amount) returns()
func (_RewardDistributor *RewardDistributorSession) PostReward(root [32]byte, amount *big.Int) (*types.Transaction, error) {
	return _RewardDistributor.Contract.PostReward(&_RewardDistributor.TransactOpts, root, amount)
}

// PostReward is a paid mutator transaction binding the contract method 0xeb630dd3.
//
// Solidity: function postReward(bytes32 root, uint256 amount) returns()
func (_RewardDistributor *RewardDistributorTransactorSession) PostReward(root [32]byte, amount *big.Int) (*types.Transaction, error) {
	return _RewardDistributor.Contract.PostReward(&_RewardDistributor.TransactOpts, root, amount)
}

// Setup is a paid mutator transaction binding the contract method 0xf00e5686.
//
// Solidity: function setup(address _safe, uint256 _posterFee, address _rewardToken) returns()
func (_RewardDistributor *RewardDistributorTransactor) Setup(opts *bind.TransactOpts, _safe common.Address, _posterFee *big.Int, _rewardToken common.Address) (*types.Transaction, error) {
	return _RewardDistributor.contract.Transact(opts, "setup", _safe, _posterFee, _rewardToken)
}

// Setup is a paid mutator transaction binding the contract method 0xf00e5686.
//
// Solidity: function setup(address _safe, uint256 _posterFee, address _rewardToken) returns()
func (_RewardDistributor *RewardDistributorSession) Setup(_safe common.Address, _posterFee *big.Int, _rewardToken common.Address) (*types.Transaction, error) {
	return _RewardDistributor.Contract.Setup(&_RewardDistributor.TransactOpts, _safe, _posterFee, _rewardToken)
}

// Setup is a paid mutator transaction binding the contract method 0xf00e5686.
//
// Solidity: function setup(address _safe, uint256 _posterFee, address _rewardToken) returns()
func (_RewardDistributor *RewardDistributorTransactorSession) Setup(_safe common.Address, _posterFee *big.Int, _rewardToken common.Address) (*types.Transaction, error) {
	return _RewardDistributor.Contract.Setup(&_RewardDistributor.TransactOpts, _safe, _posterFee, _rewardToken)
}

// UpdatePosterFee is a paid mutator transaction binding the contract method 0xb19050bd.
//
// Solidity: function updatePosterFee(uint256 newFee) returns()
func (_RewardDistributor *RewardDistributorTransactor) UpdatePosterFee(opts *bind.TransactOpts, newFee *big.Int) (*types.Transaction, error) {
	return _RewardDistributor.contract.Transact(opts, "updatePosterFee", newFee)
}

// UpdatePosterFee is a paid mutator transaction binding the contract method 0xb19050bd.
//
// Solidity: function updatePosterFee(uint256 newFee) returns()
func (_RewardDistributor *RewardDistributorSession) UpdatePosterFee(newFee *big.Int) (*types.Transaction, error) {
	return _RewardDistributor.Contract.UpdatePosterFee(&_RewardDistributor.TransactOpts, newFee)
}

// UpdatePosterFee is a paid mutator transaction binding the contract method 0xb19050bd.
//
// Solidity: function updatePosterFee(uint256 newFee) returns()
func (_RewardDistributor *RewardDistributorTransactorSession) UpdatePosterFee(newFee *big.Int) (*types.Transaction, error) {
	return _RewardDistributor.Contract.UpdatePosterFee(&_RewardDistributor.TransactOpts, newFee)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_RewardDistributor *RewardDistributorTransactor) Fallback(opts *bind.TransactOpts, calldata []byte) (*types.Transaction, error) {
	return _RewardDistributor.contract.RawTransact(opts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_RewardDistributor *RewardDistributorSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _RewardDistributor.Contract.Fallback(&_RewardDistributor.TransactOpts, calldata)
}

// Fallback is a paid mutator transaction binding the contract fallback function.
//
// Solidity: fallback() payable returns()
func (_RewardDistributor *RewardDistributorTransactorSession) Fallback(calldata []byte) (*types.Transaction, error) {
	return _RewardDistributor.Contract.Fallback(&_RewardDistributor.TransactOpts, calldata)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_RewardDistributor *RewardDistributorTransactor) Receive(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _RewardDistributor.contract.RawTransact(opts, nil) // calldata is disallowed for receive function
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_RewardDistributor *RewardDistributorSession) Receive() (*types.Transaction, error) {
	return _RewardDistributor.Contract.Receive(&_RewardDistributor.TransactOpts)
}

// Receive is a paid mutator transaction binding the contract receive function.
//
// Solidity: receive() payable returns()
func (_RewardDistributor *RewardDistributorTransactorSession) Receive() (*types.Transaction, error) {
	return _RewardDistributor.Contract.Receive(&_RewardDistributor.TransactOpts)
}

// RewardDistributorDepositIterator is returned from FilterDeposit and is used to iterate over the raw logs and unpacked data for Deposit events raised by the RewardDistributor contract.
type RewardDistributorDepositIterator struct {
	Event *RewardDistributorDeposit // Event containing the contract specifics and raw log

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
func (it *RewardDistributorDepositIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RewardDistributorDeposit)
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
		it.Event = new(RewardDistributorDeposit)
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
func (it *RewardDistributorDepositIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RewardDistributorDepositIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RewardDistributorDeposit represents a Deposit event raised by the RewardDistributor contract.
type RewardDistributorDeposit struct {
	Recipient common.Address
	Amount    *big.Int
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterDeposit is a free log retrieval operation binding the contract event 0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c.
//
// Solidity: event Deposit(address recipient, uint256 amount)
func (_RewardDistributor *RewardDistributorFilterer) FilterDeposit(opts *bind.FilterOpts) (*RewardDistributorDepositIterator, error) {

	logs, sub, err := _RewardDistributor.contract.FilterLogs(opts, "Deposit")
	if err != nil {
		return nil, err
	}
	return &RewardDistributorDepositIterator{contract: _RewardDistributor.contract, event: "Deposit", logs: logs, sub: sub}, nil
}

// WatchDeposit is a free log subscription operation binding the contract event 0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c.
//
// Solidity: event Deposit(address recipient, uint256 amount)
func (_RewardDistributor *RewardDistributorFilterer) WatchDeposit(opts *bind.WatchOpts, sink chan<- *RewardDistributorDeposit) (event.Subscription, error) {

	logs, sub, err := _RewardDistributor.contract.WatchLogs(opts, "Deposit")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RewardDistributorDeposit)
				if err := _RewardDistributor.contract.UnpackLog(event, "Deposit", log); err != nil {
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
// Solidity: event Deposit(address recipient, uint256 amount)
func (_RewardDistributor *RewardDistributorFilterer) ParseDeposit(log types.Log) (*RewardDistributorDeposit, error) {
	event := new(RewardDistributorDeposit)
	if err := _RewardDistributor.contract.UnpackLog(event, "Deposit", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RewardDistributorPosterFeeUpdatedIterator is returned from FilterPosterFeeUpdated and is used to iterate over the raw logs and unpacked data for PosterFeeUpdated events raised by the RewardDistributor contract.
type RewardDistributorPosterFeeUpdatedIterator struct {
	Event *RewardDistributorPosterFeeUpdated // Event containing the contract specifics and raw log

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
func (it *RewardDistributorPosterFeeUpdatedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RewardDistributorPosterFeeUpdated)
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
		it.Event = new(RewardDistributorPosterFeeUpdated)
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
func (it *RewardDistributorPosterFeeUpdatedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RewardDistributorPosterFeeUpdatedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RewardDistributorPosterFeeUpdated represents a PosterFeeUpdated event raised by the RewardDistributor contract.
type RewardDistributorPosterFeeUpdated struct {
	OldFee *big.Int
	NewFee *big.Int
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterPosterFeeUpdated is a free log retrieval operation binding the contract event 0x7c7423dff6eff60ac491456a649034ee92866801bb236290a4b9190e370e8952.
//
// Solidity: event PosterFeeUpdated(uint256 oldFee, uint256 newFee)
func (_RewardDistributor *RewardDistributorFilterer) FilterPosterFeeUpdated(opts *bind.FilterOpts) (*RewardDistributorPosterFeeUpdatedIterator, error) {

	logs, sub, err := _RewardDistributor.contract.FilterLogs(opts, "PosterFeeUpdated")
	if err != nil {
		return nil, err
	}
	return &RewardDistributorPosterFeeUpdatedIterator{contract: _RewardDistributor.contract, event: "PosterFeeUpdated", logs: logs, sub: sub}, nil
}

// WatchPosterFeeUpdated is a free log subscription operation binding the contract event 0x7c7423dff6eff60ac491456a649034ee92866801bb236290a4b9190e370e8952.
//
// Solidity: event PosterFeeUpdated(uint256 oldFee, uint256 newFee)
func (_RewardDistributor *RewardDistributorFilterer) WatchPosterFeeUpdated(opts *bind.WatchOpts, sink chan<- *RewardDistributorPosterFeeUpdated) (event.Subscription, error) {

	logs, sub, err := _RewardDistributor.contract.WatchLogs(opts, "PosterFeeUpdated")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RewardDistributorPosterFeeUpdated)
				if err := _RewardDistributor.contract.UnpackLog(event, "PosterFeeUpdated", log); err != nil {
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

// ParsePosterFeeUpdated is a log parse operation binding the contract event 0x7c7423dff6eff60ac491456a649034ee92866801bb236290a4b9190e370e8952.
//
// Solidity: event PosterFeeUpdated(uint256 oldFee, uint256 newFee)
func (_RewardDistributor *RewardDistributorFilterer) ParsePosterFeeUpdated(log types.Log) (*RewardDistributorPosterFeeUpdated, error) {
	event := new(RewardDistributorPosterFeeUpdated)
	if err := _RewardDistributor.contract.UnpackLog(event, "PosterFeeUpdated", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RewardDistributorRewardClaimedIterator is returned from FilterRewardClaimed and is used to iterate over the raw logs and unpacked data for RewardClaimed events raised by the RewardDistributor contract.
type RewardDistributorRewardClaimedIterator struct {
	Event *RewardDistributorRewardClaimed // Event containing the contract specifics and raw log

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
func (it *RewardDistributorRewardClaimedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RewardDistributorRewardClaimed)
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
		it.Event = new(RewardDistributorRewardClaimed)
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
func (it *RewardDistributorRewardClaimedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RewardDistributorRewardClaimedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RewardDistributorRewardClaimed represents a RewardClaimed event raised by the RewardDistributor contract.
type RewardDistributorRewardClaimed struct {
	Recipient common.Address
	Amount    *big.Int
	Claimer   common.Address
	Raw       types.Log // Blockchain specific contextual infos
}

// FilterRewardClaimed is a free log retrieval operation binding the contract event 0xf80b6d248ca65e589d3f24c7ce36e2df22ba16ba4e7656aad67e114abbe971d2.
//
// Solidity: event RewardClaimed(address recipient, uint256 amount, address claimer)
func (_RewardDistributor *RewardDistributorFilterer) FilterRewardClaimed(opts *bind.FilterOpts) (*RewardDistributorRewardClaimedIterator, error) {

	logs, sub, err := _RewardDistributor.contract.FilterLogs(opts, "RewardClaimed")
	if err != nil {
		return nil, err
	}
	return &RewardDistributorRewardClaimedIterator{contract: _RewardDistributor.contract, event: "RewardClaimed", logs: logs, sub: sub}, nil
}

// WatchRewardClaimed is a free log subscription operation binding the contract event 0xf80b6d248ca65e589d3f24c7ce36e2df22ba16ba4e7656aad67e114abbe971d2.
//
// Solidity: event RewardClaimed(address recipient, uint256 amount, address claimer)
func (_RewardDistributor *RewardDistributorFilterer) WatchRewardClaimed(opts *bind.WatchOpts, sink chan<- *RewardDistributorRewardClaimed) (event.Subscription, error) {

	logs, sub, err := _RewardDistributor.contract.WatchLogs(opts, "RewardClaimed")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RewardDistributorRewardClaimed)
				if err := _RewardDistributor.contract.UnpackLog(event, "RewardClaimed", log); err != nil {
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

// ParseRewardClaimed is a log parse operation binding the contract event 0xf80b6d248ca65e589d3f24c7ce36e2df22ba16ba4e7656aad67e114abbe971d2.
//
// Solidity: event RewardClaimed(address recipient, uint256 amount, address claimer)
func (_RewardDistributor *RewardDistributorFilterer) ParseRewardClaimed(log types.Log) (*RewardDistributorRewardClaimed, error) {
	event := new(RewardDistributorRewardClaimed)
	if err := _RewardDistributor.contract.UnpackLog(event, "RewardClaimed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// RewardDistributorRewardPostedIterator is returned from FilterRewardPosted and is used to iterate over the raw logs and unpacked data for RewardPosted events raised by the RewardDistributor contract.
type RewardDistributorRewardPostedIterator struct {
	Event *RewardDistributorRewardPosted // Event containing the contract specifics and raw log

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
func (it *RewardDistributorRewardPostedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(RewardDistributorRewardPosted)
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
		it.Event = new(RewardDistributorRewardPosted)
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
func (it *RewardDistributorRewardPostedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *RewardDistributorRewardPostedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// RewardDistributorRewardPosted represents a RewardPosted event raised by the RewardDistributor contract.
type RewardDistributorRewardPosted struct {
	Root   [32]byte
	Amount *big.Int
	Poster common.Address
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterRewardPosted is a free log retrieval operation binding the contract event 0x88d468d3eafea83d2406f714eb4c2737e374f70e2f01fe43ec07e118e28d7525.
//
// Solidity: event RewardPosted(bytes32 root, uint256 amount, address poster)
func (_RewardDistributor *RewardDistributorFilterer) FilterRewardPosted(opts *bind.FilterOpts) (*RewardDistributorRewardPostedIterator, error) {

	logs, sub, err := _RewardDistributor.contract.FilterLogs(opts, "RewardPosted")
	if err != nil {
		return nil, err
	}
	return &RewardDistributorRewardPostedIterator{contract: _RewardDistributor.contract, event: "RewardPosted", logs: logs, sub: sub}, nil
}

// WatchRewardPosted is a free log subscription operation binding the contract event 0x88d468d3eafea83d2406f714eb4c2737e374f70e2f01fe43ec07e118e28d7525.
//
// Solidity: event RewardPosted(bytes32 root, uint256 amount, address poster)
func (_RewardDistributor *RewardDistributorFilterer) WatchRewardPosted(opts *bind.WatchOpts, sink chan<- *RewardDistributorRewardPosted) (event.Subscription, error) {

	logs, sub, err := _RewardDistributor.contract.WatchLogs(opts, "RewardPosted")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(RewardDistributorRewardPosted)
				if err := _RewardDistributor.contract.UnpackLog(event, "RewardPosted", log); err != nil {
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

// ParseRewardPosted is a log parse operation binding the contract event 0x88d468d3eafea83d2406f714eb4c2737e374f70e2f01fe43ec07e118e28d7525.
//
// Solidity: event RewardPosted(bytes32 root, uint256 amount, address poster)
func (_RewardDistributor *RewardDistributorFilterer) ParseRewardPosted(log types.Log) (*RewardDistributorRewardPosted, error) {
	event := new(RewardDistributorRewardPosted)
	if err := _RewardDistributor.contract.UnpackLog(event, "RewardPosted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

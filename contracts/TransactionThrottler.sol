// SPDX-License-Identifier: MIT

pragma solidity ^0.6.12;

// import '@openzeppelin/contracts/access/Ownable.sol';
import '@openzeppelin/contracts/access/AccessControl.sol';

contract TransactionThrottler is AccessControl /*Ownable*/ {
    bool private _initlialized;
    bool private _restrictionActive;
    uint256 private _tradingStart;
    uint256 private _maxTransferAmount;
    uint256 private constant _delayBetweenTx = 30;
    mapping(address => bool) private _isWhitelisted;
    mapping(address => bool) private _isUnthrottled;
    mapping(address => uint256) private _previousTx;

    event TradingTimeChanged(uint256 tradingTime);
    event RestrictionActiveChanged(bool active);
    event MaxTransferAmountChanged(uint256 maxTransferAmount);
    event MarkedWhitelisted(address indexed account, bool isWhitelisted);
    event MarkedUnthrottled(address indexed account, bool isUnthrottled);

    function initAntibot(uint256 tradingStart, uint256 maxTransferAmount, bool _active) external /*onlyOwner()*/ {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Protection: must have admin role");
        require(!_initlialized, "Protection: Already initialized");
        _initlialized = true;
        _isUnthrottled[msg.sender] = true;
        _tradingStart = tradingStart;
        _maxTransferAmount = maxTransferAmount;
        _restrictionActive = _active;

        emit MarkedUnthrottled(msg.sender, true);
        emit TradingTimeChanged(_tradingStart);
        emit MaxTransferAmountChanged(_maxTransferAmount);
        emit RestrictionActiveChanged(_restrictionActive);
    }

    function setTradingStart(uint256 _time) external /*onlyOwner()*/ {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Protection: must have admin role");
        require(_tradingStart > block.timestamp, "Protection: To late");
        _tradingStart = _time;
        emit TradingTimeChanged(_tradingStart);
    }

    function setMaxTransferAmount(uint256 _amount) external /*onlyOwner()*/ {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Protection: must have admin role");
        _maxTransferAmount = _amount;
        emit MaxTransferAmountChanged(_maxTransferAmount);
    }

    function setRestrictionActive(bool _active) external /*onlyOwner()*/ {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Protection: must have admin role");
        _restrictionActive = _active;
        emit RestrictionActiveChanged(_restrictionActive);
    }

    function unthrottleAccount(address _account, bool _unthrottled) external /*onlyOwner()*/ {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Protection: must have admin role");
        // require(_account != address(0), "Zero address");
        _isUnthrottled[_account] = _unthrottled;
        emit MarkedUnthrottled(_account, _unthrottled);
    }

    function isUnthrottled(address account) external view returns (bool) {
        return _isUnthrottled[account];
    }

    function whitelistAccount(address _account, bool _whitelisted) external /*onlyOwner()*/ {
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Protection: must have admin role");
        // require(_account != address(0), "Zero address");
        _isWhitelisted[_account] = _whitelisted;
        emit MarkedWhitelisted(_account, _whitelisted);
    }

    function isWhitelisted(address account) external view returns (bool) {
        return _isWhitelisted[account];
    }

    modifier transactionThrottler(
        address sender,
        address recipient,
        uint256 amount
    ) {
        require(sender != recipient, "sender is recipient");
        if (_restrictionActive && !_isUnthrottled[recipient] && !_isUnthrottled[sender]) {
            require(block.timestamp >= _tradingStart, "Protection: Transfers disabled");

            if (_maxTransferAmount > 0) {
                require(amount <= _maxTransferAmount, "Protection: Limit exceeded");
            }

            if (!_isWhitelisted[recipient]) {
                require(_previousTx[recipient] + _delayBetweenTx <= block.timestamp, "Protection: 30 sec/tx allowed");
                _previousTx[recipient] = block.timestamp;
            }

            if (!_isWhitelisted[sender]) {
                require(_previousTx[sender] + _delayBetweenTx <= block.timestamp, "Protection: 30 sec/tx allowed");
                _previousTx[sender] = block.timestamp;
            }
        }
        _;
    }
}
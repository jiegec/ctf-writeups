RedbudToken1 - Welcome 150 points
================

题意
-------------

Welcome to the blockchain world!

We publish RedbudToken in Ethereum Ropsten testnet. The smart contract address is 0x29047AA8B731cd5474E06b6c1Ff8eF03191fCBb2, and the source code is in the attachment. You can get first flag if you have earned any RedbudToken. Check your RedbudToken balance and get flag through the following link.

http://host:port/account/<address>

example: http://host:port/account/0x1Bc1eE741b3d2047543f5971AD75340734C14413

attachment: redbudtoken.zip

解题步骤
-------------

附件中有 `redbudtoken.sol` ：

```
pragma solidity ^0.4.24;

contract RedbudToken{
    uint totalRedbud = 10**50;
    mapping(address => uint256) public balances;
    address keeper;
    
     constructor() public {
         keeper = msg.sender;
     }
      
      function mint(address _to, uint256 _amount) public returns(bool) {
          require(_to != 0x0);
          require(_amount > 0);
          require(msg.sender == keeper);
          require(_amount <= totalRedbud);
          totalRedbud -= _amount;
          balances[_to] += _amount;
          assert(balances[_to] < 10**7);
          return true;
      }
      
      function balanceOf(address _who) public constant returns(uint256) {
          return balances[_who];
      }
}

contract RedbudAllocation{
    
    uint256 numbers;
    address owner; // storage[0x01]
    mapping(address => uint256) public luckyChips; // storage[hash(addr, 0x2)]
    mapping(address => uint256) public lockedAmount; // storage[hash(addr, 0x3)]
    mapping(address => uint256) public lockedTime; // storage[hash(addr, 0x4)]
    uint256 public initTime; // storage[0x5] 0x04115187 func_030D
    RedbudToken public token; // storage[0x6]
    luckyMan[] luckyLog;

    struct luckyMan{
        uint256 _amount;
        address _who;
    }
    
    constructor() public {
        owner=msg.sender;
        initTime = now;
        token = new RedbudToken();
    }
    
    modifier onlyOwner {
        if (msg.sender != owner)
            revert();
        _;
    }
    
    function welcomeBonus() public returns(bool) {
        require(token.balanceOf(msg.sender) < 10);
        luckyChips[msg.sender] = 10;
        if(token.mint(msg.sender, 10)){
            numbers += 1;
            return true;
        }
        return false;
    }
    
    function luckyBonus(uint guess) public returns(bool) {
        require(luckyChips[msg.sender] > 0);
        luckyChips[msg.sender] -= 1;
        uint random = uint(keccak256(now, msg.sender, numbers)) % 10;
        if (guess == random){
            token.mint(msg.sender, 100);
            luckyMan lucky;
            lucky._amount = 100;
            lucky._who = msg.sender;
            luckyLog.push(lucky);
            return true;
        }
        return false;   
    }

    function diamondBonus(uint256 _locktime) public onlyOwner returns(bool) {
        require(_locktime > 1 years);
        lockedAmount[msg.sender] = 10**6;
        lockedTime[msg.sender] = _locktime;
        return true;
    }

    function unlock() public returns(bool) { // 0xa69df4b5 func_067E
        require(now >= initTime + lockedTime[msg.sender]);
        // block.timestamp < storage[0x5] + storage[hash(address)] then revert
        return token.mint(msg.sender, lockedAmount[msg.sender]);
    } 
    
}
```

根据 `ethervm.io` 在线的反编译，找到 `welcomeBonus` 的地址 `0xf5112f87` ，在测试网络上领取一个 `ETH` 之后进行转账即可。交易确认后获得 `Flag: THUCTF{W31c0M3_7o_61oCkcH41n_cH4lL3n9e}` 。
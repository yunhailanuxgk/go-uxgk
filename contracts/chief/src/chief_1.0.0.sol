pragma solidity >=0.5.0 <=0.5.3;

/* for remix
import "github.com/SmartMeshFoundation/Spectrum/contracts/chief/src/chief_abs_s0.5.sol"; // for remix
import "github.com/SmartMeshFoundation/Spectrum/contracts/chief/src/chief_base_s0.5_v0.0.1.sol"; // for remix
*/


/* local */
import "./chief_abs_s0.5.sol";
import "./chief_base_s0.5_v0.0.1.sol";

contract TribeChief_1_0_0 is Chief {

    string vsn = "1.0.0";

    struct BlackMember {
        address addr;
        uint score;
        uint number;
    }

    ChiefBase_1_0_0 private base;


    address[] public  _signerList;
    address[] public  _nextRoundSignerList;
    uint  public  blockNumber;



    mapping(address => uint)   signersMap;

    constructor(address baseAddress, address pocAddress,uint startBlockNumber) public {
        base = ChiefBase_1_0_0(baseAddress);
        base.init(pocAddress, address(this));
        blockNumber=startBlockNumber;

        address[] memory leaderList = base.takeLeaderList();
        require(leaderList.length > 0);

        signersMap[leaderList[0]] = 1;
        _signerList.push(leaderList[0]);

        for (uint i = _signerList.length; i < base.takeSignerLimit(); i++) {
            _signerList.push(address(0));
        }

    }

    modifier allow() {
        address _addr = msg.sender;
        require(uint160(_addr) != uint160(0));
        require(signersMap[_addr] > 0 || base.isLeader(_addr));
        _;
    }

    function pushNextRoundSigner(address addr)  private {
        if (_nextRoundSignerList.length < base.takeVolunteerLimit()) {
            _nextRoundSignerList.push(addr);
        } else{
            revert("next round signer too much");
        }
    }

    function pushSigner(address signer ) private {
        if (_signerList.length < base.takeSignerLimit()) {
            _signerList.push(signer);
            signersMap[signer] = 1;
        } else{
            revert("too many signer");
        }
    }

    function clean_all_signer_and_get0()  private returns (address) {
        address signer0=_signerList[0];
        for (uint i = 0;i<_signerList.length;i++) {
            signersMap[_signerList[i]]=0;
            _signerList[i]=address(0);
        }
        _signerList.length=0;
        return signer0;
    }

    function genSigners_set_leader(address signer0 ) private {
        address[] memory leaders = base.takeLeaderList();
        for (uint i = 0; i < leaders.length; i++) {
            address l = leaders[i];
            if (signer0 == l) {
                if (i == leaders.length - 1) {
                    pushSigner(leaders[0]);
                } else {
                    pushSigner(leaders[i + 1]);
                }
                return;
            }
        }
        revert("signer0 must exist in leader list");
    }

    function genSigners_v2s() private {
        for (uint i = 0; i < _nextRoundSignerList.length; i++) {
            address v = _nextRoundSignerList[i];
            pushSigner(v);
        }
        for (uint i = _signerList.length; i < base.takeSignerLimit(); i++) {
            _signerList.push(address(0));
        }
    }

    function genSigners_clean_next_round_signers() private {
        for (uint i =0; i< _nextRoundSignerList.length; i++) {
            _nextRoundSignerList[i]=address(0);
        }
        _nextRoundSignerList.length=0;
    }

    function genSigners_clean_blackList() private {
        base.pocCleanBlackList();
    }

    function genSigners() private  {
        address signer0=clean_all_signer_and_get0();
        require(signer0!=address(0),"signer0 must not be zero");
        genSigners_set_leader(signer0);
        genSigners_v2s();
        genSigners_clean_next_round_signers();
    }

    function update(address volunteer) public allow() {

        blockNumber = block.number;

        uint l = base.takeSignerLimit();
        uint signerIdx = uint(blockNumber % l);
        address si = _signerList[signerIdx];

        if (signerIdx > uint(0)) { //leader不是选出来的

            if (uint160(volunteer) != uint160(0)) {
                pushNextRoundSigner(volunteer);
            }
            if (si != address(0) && msg.sender != si) {
                if (base.pocAddStop(si) > 0) {
                    base.pocAddBlackList(si);
                }
                delete signersMap[si];
                _signerList[signerIdx] = address(0);
            }
        }

        if (signerIdx == (l - 1)) {
            genSigners();
        }

        if (block.number%getEpoch()==0){
            genSigners_clean_blackList();
        }
    }

    function getStatus() public view returns (
        address[] memory signerList,
        address[] memory blackList,
        uint[] memory scoreList,
        uint[] memory numberList,
        uint totalVolunteer,
        uint number
    ) {
        scoreList = new uint[](_signerList.length);
        numberList = new uint[](_signerList.length);
        for (uint i = 0; i < _signerList.length; i ++) {
            scoreList[i] = 0;
            numberList[i] = signersMap[_signerList[i]];
        }
        blackList = base.pocGetBlackList();
        signerList = _signerList;
        number = blockNumber;
        totalVolunteer = _nextRoundSignerList.length;
    }

    function version() public view returns (string memory) {return vsn;}

    function getSignerLimit() public view returns (uint) {return base.takeSignerLimit();}

    function getEpoch() public view returns (uint) {return base.takeEpoch();}

    function getVolunteerLimit() public view returns (uint) {return base.takeVolunteerLimit();}

    function getVolunteers() public view returns (
        address[] memory volunteerList,
        uint[] memory weightList,
        uint length
    ){
        (volunteerList,length)=getNextRoundSignerList();
        weightList = new uint[](length);
    }
    function getNextRoundSignerList() public view returns (
        address[] memory nextRoundSignerList,
        uint length
    ) {
        nextRoundSignerList=_nextRoundSignerList;
        length=nextRoundSignerList.length;
    }

    function filterVolunteer(address[] memory volunteers) public view returns (uint[] memory result) {}
}

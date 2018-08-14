// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>

#include <arith_uint256.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1529260981, nBits=1d00ffff, nNonce=516443, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Yacoin 2.0 is finally here!!!";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857YACOIN8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 1401600;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("f92ece26f38e6c12e40d99f60ac794306dd4e45b02ad634e4f041bd631573a4e");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // 1 day
        consensus.nPowTargetSpacing = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nPowDGWHeight = 250;
        consensus.nRuleChangeActivationThreshold = 1964; 
        consensus.nMinerConfirmationWindow = 2064; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
       // consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000002ebcfe2dd9eff82666");

        // By default assume that the signatures in ancestors of this block are valid.
       // consensus.defaultAssumeValid = uint256S("0xf92ece26f38e6c12e40d99f60ac794306dd4e45b02ad634e4f041bd631573a4e"); // TODO, update when we have some blocks

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x66;
        pchMessageStart[1] = 0x69;
        pchMessageStart[2] = 0x6b;
        pchMessageStart[3] = 0x61;
        nDefaultPort = 7698;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1529457054, 670525, 0x1e0ffff0, 1, 100 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();        
        assert(consensus.hashGenesisBlock == uint256S("0xf92ece26f38e6c12e40d99f60ac794306dd4e45b02ad634e4f041bd631573a4e"));
        assert(genesis.hashMerkleRoot == uint256S("0xf833840fb836113c0b12255ff80149c56529f8c0923dbf26353a4fc39a950842"));

        // Note that of those with the service bits flag, most only support a subset of possible options
//        vSeeds.emplace_back("seed-a.litecoin.loshan.co.uk");
//        vSeeds.emplace_back("dnsseed.thrasher.io");
//        vSeeds.emplace_back("dnsseed.litecointools.com");
//        vSeeds.emplace_back("dnsseed.litecoinpool.org");
//        vSeeds.emplace_back("dnsseed.koin-project.com");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,77);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,139);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,150);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,196);

        base58Prefixes[EXT_PUBLIC_KEY] = {0x24, 0x48, 0x62, 0x8E};
        base58Prefixes[EXT_SECRET_KEY] = {0x14, 0x38, 0x5D, 0x74};

        bech32_hrp = "yac";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;        
        fMiningRequiresPeers = true;

        checkpointData = {
            {
            //    {  1500, uint256S("0x")},

            }
        };

        chainTxData = ChainTxData{
            // Data as of block 59c9b9d3fec105bdc716d84caa7579503d5b05b73618d0bf2d5fa639f780a011 (height 1353397).
            1529457054, // * UNIX timestamp of last known number of transactions
            0,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            0.00     // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 1401600;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("5907ce73b3bc50521f64e4a68507d7ec571b5d7d4ed7312068a9f97cb6547c25");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
      //  consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // 1 day
        consensus.nPowTargetSpacing = 1.5* 60;
        consensus.fPowAllowMinDifficultyBlocks = true;

        consensus.fPowNoRetargeting = false;
        consensus.nPowDGWHeight = 25;
        consensus.nRuleChangeActivationThreshold = 1548; 
        consensus.nMinerConfirmationWindow = 2064; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
      //  consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000007d006a402163e");

        // By default assume that the signatures in ancestors of this block are valid.
       // consensus.defaultAssumeValid = uint256S("0xa0afbded94d4be233e191525dc2d467af5c7eab3143c852c3cd549831022aad6"); //343833
        //consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x59;
        pchMessageStart[1] = 0x41;
        pchMessageStart[2] = 0x43;
        pchMessageStart[3] = 0x54;
        nDefaultPort = 17698;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1530473312, 825061, 0x1e0ffff0, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x5907ce73b3bc50521f64e4a68507d7ec571b5d7d4ed7312068a9f97cb6547c25"));
        assert(genesis.hashMerkleRoot == uint256S("0xf833840fb836113c0b12255ff80149c56529f8c0923dbf26353a4fc39a950842"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
//        vSeeds.emplace_back("testnet-seed.litecointools.com");
//        vSeeds.emplace_back("seed-b.litecoin.loshan.co.uk");
//        vSeeds.emplace_back("dnsseed-testnet.thrasher.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,211);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,156);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,48);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,219);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x14, 0x25, 0x37, 0x4F};
        base58Prefixes[EXT_SECRET_KEY] = {0xA4, 0xB5, 0xC3, 0xD4};

        bech32_hrp = "tyac";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        //fMiningRequiresPeers = true;

        // YACOIN DEBUG
        fMiningRequiresPeers = false;



        checkpointData = (CCheckpointData) {
            {
               {0, uint256S("5907ce73b3bc50521f64e4a68507d7ec571b5d7d4ed7312068a9f97cb6547c25")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block a0afbded94d4be233e191525dc2d467af5c7eab3143c852c3cd549831022aad6 (height 343833)
            1530473312,
            0,
            0.00
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60;
        consensus.nPowTargetSpacing = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; 
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x59;
        pchMessageStart[1] = 0x41;
        pchMessageStart[2] = 0x43;
        pchMessageStart[3] = 0x52;
        nDefaultPort = 19768;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1530473312, 0, 0x207fffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0xf76ac1f3df974c8ed7ccecd06ab6dbd0bc8dbe7acae4a15c483765e9146cb1fb"));
        assert(genesis.hashMerkleRoot == uint256S("0xf833840fb836113c0b12255ff80149c56529f8c0923dbf26353a4fc39a950842"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = {
            {
                {0, uint256S("f76ac1f3df974c8ed7ccecd06ab6dbd0bc8dbe7acae4a15c483765e9146cb1fb")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,151);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,146);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,38);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,229);
        base58Prefixes[EXT_PUBLIC_KEY] = {0xC4, 0xD5, 0xE7, 0xFF};
        base58Prefixes[EXT_SECRET_KEY] = {0x54, 0x65, 0x73, 0x84};

        bech32_hrp = "ryac";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

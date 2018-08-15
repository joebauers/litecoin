// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2018 The Yacoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>

extern "C" {
#include <crypto/scrypt-jane/scrypt-jane.h>
}

#include <crypto/common.h>
#include <crypto/scrypt.h>

#include <arith_uint256.h>

static int block_length = 63;

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

int CBlockHeader::GetNfactor() const
{

    std::string spb = hashPrevBlock.ToString();
    std::string lasthashchar = spb.substr(block_length,1);

    unsigned char Nfactor = 19;
      if((spb == "0000000000000000000000000000000000000000000000000000000000000000")){
                  Nfactor = 4;}  // GENESIS

// Possible future implementation
      else if((lasthashchar == "0") || (lasthashchar == "6") || (lasthashchar == "a")){
               Nfactor = 22;}
      else if((lasthashchar == "1") || (lasthashchar == "b")){
               Nfactor = 21;}
      else if((lasthashchar == "2") || (lasthashchar == "7") || (lasthashchar == "c")){
               Nfactor = 20;}
      else if((lasthashchar == "3") || (lasthashchar == "d")){
               Nfactor = 19;}
      else if((lasthashchar == "4") || (lasthashchar == "9") || (lasthashchar == "e")){
               Nfactor = 20;}
      else if((lasthashchar == "5") || (lasthashchar == "f")){
               Nfactor = 21;}
      else if((lasthashchar == "8")){
               Nfactor = 22;}

      return Nfactor;
}


uint256 CBlockHeader::GetPoWHash() const
{
    uint256 lhash;
    uint256 yhash;
    uint256 finalhash;

    std::string spb = hashPrevBlock.ToString();

      const char *salt(spb.c_str());
      size_t salt_len = block_length;
      unsigned char rfactor = 0;
      unsigned char pfactor = 0;
      size_t bytes = 32;

      CBlockHeader block_header;

    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(lhash));
    scrypt_jane(CVOIDBEGIN(nVersion), sizeof(block_header), salt, salt_len, GetNfactor(),  rfactor, pfactor,  UINTBEGIN(yhash), bytes);

    arith_uint256 ArithLTCHash = UintToArith256(lhash);
    arith_uint256 ArithYACHash = UintToArith256(yhash);
    arith_uint256 CombinedHash = (ArithLTCHash + ArithYACHash);

    finalhash = ArithToUint256(CombinedHash);    

    return finalhash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

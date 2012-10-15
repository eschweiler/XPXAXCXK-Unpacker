/* ============================================================================
* Copyright (c) 2012, Sebastian Eschweiler <advanced(dot)malware<dot>analyst[at]gmail.com>
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the <organization> nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
* =============================================================================
*/

#pragma once
#include <vector>
#include <memory>

#include <gtest/gtest_prod.h>

#include "ChunkAssembler.h"

#include "Base64.h"
#include "Decompressor.h"
#include "CryptAnalyzer.h"

using namespace std;
class XPackUnpacker
{
public:

	static bool isPackedByXpack(const ustring& s);
	static ustring unpack(const ustring& s); //TODO: test


private:
	FRIEND_TEST(XpackUnpackerTest, testRevealCode1);
	FRIEND_TEST(XpackUnpackerTest, testRevealCode2);
	FRIEND_TEST(XpackUnpackerTest, testAssemble);
	FRIEND_TEST(XpackUnpackerTest, testAssemble2);
	FRIEND_TEST(XpackUnpackerTest, testDecryptFirstRound);
	FRIEND_TEST(XpackUnpackerTest, testDecryptFirstRound2);
	FRIEND_TEST(XpackUnpackerTest, testSecondRoundAndDecompress);

	
	static ustring assemble(const ustring& s);

	static void decryptFirstRound(ustring& assembledData);
	static void decryptFirstRound(ustring& s, const unsigned char offset, const unsigned char modulus);

	static void decryptStage2b(ustring& s, const unsigned char xorValue, const unsigned char offset);

	static ustring secondRoundAndDecompress(const ustring& xpackData);

	static void decryptStage2a(ustring& s);
	static void decryptStage2a(unsigned char* base64DecodedBuffer, DWORD len);
};

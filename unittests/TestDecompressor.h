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

#include <gtest/gtest.h>
#include <Decompressor.h>
#include <tchar.h>

#include <fstream>
#include <streambuf>

class DecompressorTest : public ::testing::Test
{

public:
	DecompressorTest()
	{}

	virtual ~DecompressorTest()
	{}

	virtual void SetUp()
	{}

	virtual void TearDown()
	{}

};



TEST_F(DecompressorTest, commonCtorWithCompressedBuffer)
{
	unsigned char x[] = {0x58, 0x50, 0x58, 0x41, 0x58, 0x43, 0x58, 0x4B, 0x00, 0x36, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x48, 0x45, 0x4c, 0x4c, 0x4f};
	XpackStruct* d = (XpackStruct* ) x;

	ASSERT_EQ(d->compressedLength, 5);
	ASSERT_EQ(d->decompressedLength, 0x33600);
	ASSERT_EQ(memcmp(d->compressedBuffer, "HELLO", 5), 0);

}


TEST_F(DecompressorTest, showCase)
{
	basic_ifstream<unsigned char> t("testfiles/d5b0a448f59c3e946255333ad0ef5cc5/compressed_XPACK.bin", ios::binary);
	ustring s((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	XpackStruct* d = (XpackStruct*) s.c_str();

	ASSERT_EQ(d->compressedLength, 0x1a070);
	ASSERT_EQ(d->decompressedLength, 0x33600);
	unsigned char* compressedBuffer = d->compressedBuffer;

	unsigned char bufStart[16] = {0x00, 0x26, 0x96, 0x7C, 0x1B, 0x8C, 0xCF, 0x13, 0x1B, 0xB7, 0x34, 0x70, 0xF1, 0x0E, 0x24, 0x33};

	ASSERT_EQ(memcmp(d->compressedBuffer, bufStart, sizeof bufStart), 0);

	unsigned char bufEnd[16] = {0xB5, 0x17, 0x63, 0xD3, 0x03, 0x2E, 0x99, 0xAC, 0xB3, 0x64, 0x1A, 0xCC,	0xDE, 0x41, 0x4A, 0x00};
	ASSERT_EQ(memcmp(d->compressedBuffer + d->compressedLength - 16, bufEnd, sizeof bufStart), 0);

	ustring decompressedData = d->decompress();

	t = basic_ifstream<unsigned char>("testfiles/d5b0a448f59c3e946255333ad0ef5cc5/decompressed.bin", ios::binary);
	s = ustring((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	ASSERT_EQ(s, decompressedData);

}


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
#include <ChunkAssembler.h>

#include <fstream>
#include <streambuf>

class ChunkAssemblerTest : public ::testing::Test
{

public:
	ChunkAssemblerTest()
	{
	}

	virtual ~ChunkAssemblerTest()
	{}

	virtual void SetUp()
	{}

	virtual void TearDown()
	{}

};


TEST_F(ChunkAssemblerTest, checkHeader)
{

	unsigned char validHeader[0x18] = {0xF6, 0x2C, 0xB2, 0x4B, 0xFA, 0xDF, 0xFF, 0xBD, 0x1F, 0x02, 0x29, 0xFC, 0xDB, 0x9A, 0x9B, 0xA1, 0x9B, 0xA6, 0x00, 0x00, 0x89, 0x37, 0x00, 0x00};
	Chunk* c = (Chunk*) validHeader;
	ASSERT_TRUE(c->isChunkHead());

	unsigned char header2[0x18] = {0x27, 0xFC, 0x2F, 0x88, 0xFF, 0xDB, 0xA7, 0xFF, 0xD9, 0x5C, 0x60, 0x54, 0xA3, 0x4C, 0x80, 0x19, 0x36, 0x4D, 0x01, 0x00, 0x89, 0x37, 0x00, 0x00};
	c = (Chunk*) header2;
	ASSERT_TRUE(c->isChunkHead());

	unsigned char header3[0x18] = {0xA3, 0x31, 0x6A, 0xDB, 0xFA, 0xDB, 0xB3, 0x79, 0x4C, 0xD3, 0x15, 0xA6, 0x90, 0x01, 0x05, 0x74, 0xE9, 0xEB, 0x00, 0x00, 0xC1, 0x05, 0x00, 0x00};
	c = (Chunk*) header3;
	ASSERT_TRUE(c->isChunkHead());

}


TEST_F(ChunkAssemblerTest, checkGetFirstChunk)
{
	
	unsigned char validHeader[0x18] = {0xF6, 0x2C, 0xB2, 0x4B, 0xFA, 0xDF, 0xFF, 0xBD, 0x1F, 0x02, 0x29, 0xFC, 0xDB, 0x9A, 0x9B, 0xA1, 0x9B, 0xA6, 0x00, 0x00, 0x89, 0x37, 0x00, 0x00};
	ustring validHeaderString(validHeader, sizeof validHeader);
	Chunk* chunk = ChunkAssembler::getFirstChunk(validHeaderString);
	ASSERT_EQ((void*) chunk, (void*) validHeaderString.c_str());

	unsigned char invalidHeader[0x18] = {0xF6, 0x2D, 0xB2, 0x4B, 0xFA, 0xDF, 0xFF, 0xBD, 0x1F, 0x02, 0x29, 0xFC, 0xDB, 0x9A, 0x9B, 0xA1, 0x9B, 0xA6, 0x00, 0x00, 0x89, 0x37, 0x00, 0x00};
	chunk = ChunkAssembler::getFirstChunk(invalidHeader);
	ASSERT_EQ((void*) chunk, (void*) NULL);

	unsigned char headerWithOffset[] = {0, 0, 0, 0, 0, 0, 0, 0xF6, 0x2C, 0xB2, 0x4B, 0xFA, 0xDF, 0xFF, 0xBD, 0x1F, 0x02, 0x29, 0xFC, 0xDB, 0x9A, 0x9B, 0xA1, 0x9B, 0xA6, 0x00, 0x00, 0x89, 0x37, 0x00, 0x00};
	ustring headerWithOffsetString(headerWithOffset, sizeof headerWithOffset);
	chunk = ChunkAssembler::getFirstChunk(headerWithOffsetString);
	ASSERT_EQ((void*) chunk, (void*) (headerWithOffsetString.c_str() + 7));

}

TEST_F(ChunkAssemblerTest, testGetHeads)
{

	basic_ifstream<unsigned char> t("testfiles/d5b0a448f59c3e946255333ad0ef5cc5/d5b0a448f59c3e946255333ad0ef5cc5", ios::binary);
	ustring s((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	vector<Chunk*> heads = ChunkAssembler::getChunkHeads(s);

	ASSERT_EQ(heads.size(), 10);

	ASSERT_EQ(heads[0]->dechunkedOffset, 0x0A69B);

	
	ASSERT_EQ(heads[9]->hash, 0xb43332b6);
	ASSERT_EQ(heads[9]->size, 0x00003789);

}


TEST_F(ChunkAssemblerTest, testAssemble)
{

	basic_ifstream<unsigned char> t("testfiles/d5b0a448f59c3e946255333ad0ef5cc5/d5b0a448f59c3e946255333ad0ef5cc5", ios::binary);
	ustring s((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	vector<Chunk*> heads = ChunkAssembler::getChunkHeads(s);

	ustring dechunkeData = ChunkAssembler::assemble(s, heads);

	t = basic_ifstream<unsigned char>("testfiles/d5b0a448f59c3e946255333ad0ef5cc5/dechunked.bin", ios::binary);
	ustring dechunked((istreambuf_iterator<unsigned char>(t)), istreambuf_iterator<unsigned char>());

	ASSERT_EQ(dechunked, dechunkeData);

}



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

#include "ChunkAssembler.h"


bool Chunk::isChunkHead()
{
	if (magic[0] && magic[1] && magic[2] && magic[3] &&
		((magic[0] ^ magic[1]) | magic[2]) == magic[4] &&
		((magic[1] ^ magic[2]) | magic[3]) == magic[5] &&
		((magic[2] ^ magic[3]) | magic[0]) == magic[6] &&
		((magic[0] ^ magic[3]) | magic[1]) == magic[7])
	{
		if (dechunkedOffset >= 0 && dechunkedOffset < 0x00f00000 &&			// assert reasonable size of dechunked offset
			size >= 0 && size <= 0x10000 &&									// assert reasonable size for chunk
			!(magic[0] == magic[1] && magic[0] == magic[2] &&				// assert not all bytes of beginning are the same
			magic[0] == magic[3] && magic[0] == magic[4] &&
			magic[0] == magic[5] && magic[0] == magic[6] &&
			magic[0] == magic[7]))
	
			return true;
	
	}

	return false;

}


vector<Chunk*> ChunkAssembler::getChunkHeads( const ustring& s )
{
	vector<Chunk*> heads;
	
	for (size_t i = 0; i < s.length(); i++)
	{
		Chunk* c = (Chunk*) (s.c_str() + i);

		if (c->isChunkHead())
		{
			heads.push_back(c);
		}
	}

	return heads;

}


ustring ChunkAssembler::assemble(const ustring& file_content, const vector<Chunk*>& chunks)
{
	
	unsigned char* tmpRes = new unsigned char[file_content.length()];

	ULONG curMax = 0;

	for (vector<Chunk*>::const_iterator i = chunks.begin(); i != chunks.end(); i++)
	{
		memcpy(tmpRes + (*i)->dechunkedOffset, (*i)->chunkData, (*i)->size);
		curMax = max(curMax, (*i)->dechunkedOffset + (*i)->size);
	}
	
	ustring dechunkedData(tmpRes, curMax);

	return dechunkedData;
}


Chunk* ChunkAssembler::getFirstChunk( const ustring& s )
{
	for (size_t i = 0; i < s.length(); i++)
	{
		Chunk* c = (Chunk*) (s.c_str() + i);
		if (c->isChunkHead())
			return c;
	}

	return NULL;
}
